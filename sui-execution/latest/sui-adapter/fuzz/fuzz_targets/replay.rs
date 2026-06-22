// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Replay one or more crash files produced by the fuzzer.
//!
//! Usage:
//!   ./replay crashes/file1 crashes/file2 ...
//!   ./replay crashes/          # all files in a directory
//!
//! For each file, prints: path | bytes | BCS decode | pipeline stage | panic? | heap delta

use std::{path::PathBuf, time::Instant};
use sui_types::transaction::ProgrammableTransaction;
use tikv_jemalloc_ctl::{epoch, stats};

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

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

fn current_heap_bytes() -> u64 {
    epoch::mib()
        .expect("jemalloc epoch mib")
        .advance()
        .expect("jemalloc epoch advance");
    stats::allocated::mib()
        .expect("jemalloc allocated mib")
        .read()
        .expect("jemalloc allocated read") as u64
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
             "file", "bytes", "stage", "heap∆", "wall_ms");
    println!("{}", "-".repeat(110));

    for path in &paths {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => { eprintln!("skip {}: {e}", path.display()); continue; }
        };
        let name = path.file_name().unwrap_or_default().to_string_lossy();

        let heap_before = current_heap_bytes();
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
                    let heap_delta = current_heap_bytes().saturating_sub(heap_before);
                    (label.to_string(), heap_delta)
                }
            }
        }));

        let wall_ms = t0.elapsed().as_millis();

        match result {
            Err(_) => {
                println!("{:<60} {:>8}  {:<12}  {:>8}  {:>8}  *** PANIC ***",
                         name, bytes.len(), "PANIC", "?", wall_ms);
            }
            Ok((stage, heap_delta)) => {
                let heap_mib = heap_delta as f64 / (1024.0 * 1024.0);
                let flag = if heap_delta > 62 * 1024 * 1024 { "  *** HEAP ***" } else { "" };
                println!("{:<60} {:>8}  {:<12}  {:>6.1} MiB  {:>8}{flag}",
                         name, bytes.len(), stage, heap_mib, wall_ms);
            }
        }
    }
}
