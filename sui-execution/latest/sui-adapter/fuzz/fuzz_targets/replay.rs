// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Replay one or more crash files produced by the fuzzer.
//!
//! Usage:
//!   ./replay crashes/file1 crashes/file2 ...
//!   ./replay crashes/          # all files in a directory
//!
//! For each file, prints: path | bytes | BCS decode | pipeline stage | panic? | RSS delta

use std::{path::PathBuf, time::Instant};
use sui_types::transaction::ProgrammableTransaction;

#[path = "fixture.rs"]
mod fixture;
use fixture::{Fixture, PipelineStage, run_typing};

// Sancov stubs — replay doesn't need coverage instrumentation.
#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_pc_guard(_guard: *mut u32) {}
#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_pc_guard_init(_start: *mut u32, _stop: *mut u32) {}
#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_pc_indir(_callee: usize) {}

fn current_anon_rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("RssAnon:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
        })
        .unwrap_or(0)
}

fn collect_paths(args: impl Iterator<Item = String>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for arg in args {
        let p = PathBuf::from(&arg);
        if p.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&p) {
                let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
                entries.sort();
                paths.extend(entries.into_iter().filter(|e| e.is_file()));
            }
        } else {
            paths.push(p);
        }
    }
    paths
}

fn main() {
    let fixture = Fixture::new();
    let paths = collect_paths(std::env::args().skip(1));
    if paths.is_empty() {
        eprintln!("usage: replay <crash_file|crashes_dir> ...");
        std::process::exit(1);
    }

    println!("{:<60} {:>8}  {:<12}  {:>8}  {:>8}",
             "file", "bytes", "stage", "anon_rss∆", "wall_ms");
    println!("{}", "-".repeat(110));

    for path in &paths {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => { eprintln!("skip {}: {e}", path.display()); continue; }
        };
        let name = path.file_name().unwrap_or_default().to_string_lossy();

        let rss_before = current_anon_rss_kb();
        let t0 = Instant::now();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match bcs::from_bytes::<ProgrammableTransaction>(&bytes) {
                Err(_) => ("decode_fail".to_string(), 0u64),
                Ok(txn) => {
                    let (stage, _) = run_typing(&fixture, txn);
                    let label = match stage {
                        PipelineStage::Linkage => "linkage_fail",
                        PipelineStage::Loading => "loading_fail",
                        PipelineStage::Typing  => "typing_ok",
                    };
                    let rss_delta = current_anon_rss_kb().saturating_sub(rss_before);
                    (label.to_string(), rss_delta)
                }
            }
        }));

        let wall_ms = t0.elapsed().as_millis();

        match result {
            Err(_) => {
                println!("{:<60} {:>8}  {:<12}  {:>8}  {:>8}  *** PANIC ***",
                         name, bytes.len(), "PANIC", "?", wall_ms);
            }
            Ok((stage, rss_delta_kb)) => {
                let rss_mib = rss_delta_kb as f64 / 1024.0;
                let flag = if rss_delta_kb > 62 * 1024 { "  *** RSS ***" } else { "" };
                println!("{:<60} {:>8}  {:<12}  {:>6.1} MiB  {:>8}{flag}",
                         name, bytes.len(), stage, rss_mib, wall_ms);
            }
        }
    }
}
