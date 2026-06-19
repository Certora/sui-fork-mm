// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Native LibAFL harness for `typing::translate_and_verify`.
//!
//! We cannot call `translate_and_verify` in true isolation: every `MoveCall` in the input carries a
//! `LoadedFunction` whose signature is produced only by the loading pass calling into the VM. So
//! the harness runs the *minimal* real pipeline — loading + translate_and_verify — against a
//! framework-only environment, and stops before the interpreter. The fuzzer-controlled input is a
//! `ProgrammableTransaction`; everything else is a fixed fixture built once per worker thread.
//!
//! What we're hunting: panics, aborts, `invariant_violation!`, and the crate's denied lints
//! (`arithmetic_side_effects` / `indexing_slicing`). A returned `Err(_)` is the normal, expected
//! outcome for most inputs and is NOT a finding.

use std::{
    io::Write as _,
    path::PathBuf,
    sync::{OnceLock, atomic::{AtomicBool, AtomicU64, Ordering}},
    time::Duration,
};

use libafl::{
    corpus::OnDiskCorpus,
    events::SimpleEventManager,
    executors::{ExitKind, InProcessForkExecutor},
    feedbacks::{
        CrashFeedback, EagerOrFeedback, MaxMapFeedback, NewHashFeedback, TimeFeedback,
        TimeoutFeedback,
    },
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{
        havoc_mutations::havoc_mutations,
        scheduled::{HavocScheduledMutator, SingleChoiceScheduledMutator},
    },
    observers::{BacktraceObserver, HarnessType, HitcountsMapObserver, TimeObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{
    AsSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_targets::std_edges_map_observer;

use sui_types::transaction::ProgrammableTransaction;

#[path = "fixture.rs"]
mod fixture;
use fixture::{Fixture, PipelineStage, run_typing};

mod ptb_mutator;
use ptb_mutator::PtbMutator;

/// SanitizerCoverage emits an indirect-call callback that `libafl_targets` only defines via its C
/// cmplog shim (not enabled here). We don't use indirect-call coverage — edge coverage from
/// trace-pc-guard is the signal — so provide a no-op so the binary links.
#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_pc_indir(_callee: usize) {}

thread_local! {
    static FIXTURE: Fixture = Fixture::new();
}

// Set once in main before any fork; read in the child from its copy of the address space.
static RECORD_STAGES: AtomicBool = AtomicBool::new(false);
static RECORD_DELTAS: AtomicBool = AtomicBool::new(false);
static RSS_LIMIT: AtomicU64 = AtomicU64::new(u64::MAX);
static STAGES_LOG_PATH: OnceLock<PathBuf> = OnceLock::new();
static DELTAS_LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Any single iteration that allocates more than this is a finding regardless of whether
/// it panics.  Set to 5× the worst-case corpus seed as measured by `gen_corpus` calibration
/// (04_make_move_vec_fan_out_255 → ~12.3 MiB → 62 MiB threshold).
/// Re-run `gen_corpus` after adding new seeds, and re-calibrate against the actual
/// RSS-delta distribution after a ~10-minute warm-up run.
const RSS_DELTA_LIMIT_BYTES: u64 = 62 * 1024 * 1024;

/// Returns current process RSS in bytes by reading `VmRSS` from `/proc/self/status`.
/// Unlike `getrusage(RUSAGE_SELF).ru_maxrss` (which is a peak-ever value on Linux),
/// this reflects the live working-set size and produces a meaningful delta.
fn current_rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
        })
        .unwrap_or(0)
        * 1024 // value is in kB
}

/// Read a deltas log (one u64 byte-count per line) and return the p99.9 value × 1.5,
/// rounded up to the nearest MiB, floored at 1 MiB.
fn threshold_from_log(path: &str) -> u64 {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    let mut vals: Vec<u64> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().parse::<u64>().unwrap_or_else(|e| panic!("bad value in {path}: {e}")))
        .collect();
    assert!(!vals.is_empty(), "{path} contains no data");
    vals.sort_unstable();
    let idx = ((vals.len() as f64 * 0.999) as usize).min(vals.len() - 1);
    let p999 = vals[idx];
    // 1.5× p99.9, rounded up to nearest MiB, floored at 1 MiB.
    let threshold = ((p999 as f64 * 1.5) as u64)
        .max(1024 * 1024)
        .div_ceil(1024 * 1024)
        * 1024 * 1024;
    eprintln!(
        "[rss-threshold] log={path}  n={}  p99.9={} KiB  threshold={} MiB",
        vals.len(),
        p999 / 1024,
        threshold / (1024 * 1024),
    );
    threshold
}

fn main() -> Result<(), libafl::Error> {
    // Anchor all relative paths to the directory containing the binary so the
    // fuzzer works correctly regardless of the shell's working directory.
    let bin_dir = std::env::current_exe()
        .expect("could not determine binary path")
        .parent()
        .expect("binary has no parent directory")
        .to_path_buf();

    let mut args = std::env::args().peekable();
    let mut record_deltas = false;
    let mut record_stages = false;
    let mut rss_threshold_log: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--record-deltas" => record_deltas = true,
            "--record-stages" => record_stages = true,
            "--rss-threshold-from" => {
                rss_threshold_log = Some(
                    args.next().expect("--rss-threshold-from requires a path argument"),
                );
            }
            _ => {}
        }
    }

    let rss_limit = match rss_threshold_log {
        Some(ref path) => threshold_from_log(path),
        None => RSS_DELTA_LIMIT_BYTES,
    };

    let corpus_dir   = bin_dir.join("corpus");
    let crashes_dir  = bin_dir.join("crashes");
    let stages_log   = bin_dir.join("pipeline_stages.log");
    let deltas_log   = bin_dir.join("rss_deltas.log");

    // Store flags and limit in globals so the forked child can read them from
    // its copy of the address space — closure captures are parent-stack references
    // and are not accessible after fork.
    RECORD_DELTAS.store(record_deltas, Ordering::Relaxed);
    RECORD_STAGES.store(record_stages, Ordering::Relaxed);
    RSS_LIMIT.store(rss_limit, Ordering::Relaxed);
    STAGES_LOG_PATH.set(stages_log.clone()).ok();
    DELTAS_LOG_PATH.set(deltas_log.clone()).ok();

    if record_deltas {
        eprintln!("[record-deltas] appending RSS deltas to {}", deltas_log.display());
    }
    if record_stages {
        eprintln!("[record-stages] appending pipeline stages to {}", stages_log.display());
    }

    // The closure run on each input (executes in the forked child).
    // Flags and limits are read from globals set before the first fork.
    let mut harness = |input: &BytesInput| {
        let rss_before = current_rss_bytes();
        let bytes = input.target_bytes();
        let decode_result = bcs::from_bytes::<ProgrammableTransaction>(bytes.as_slice());
        let stage_byte = match decode_result {
            Err(_) => b'D', // BCS decode failed — never entered the pipeline
            Ok(txn) => {
                let stage = FIXTURE.with(|fixture| {
                    let (stage, _) = run_typing(fixture, txn);
                    stage
                });
                match stage {
                    PipelineStage::Linkage => b'I', // linkage/input resolution failed
                    PipelineStage::Loading => b'L', // loading pass failed
                    PipelineStage::Typing  => b'T', // typing was reached
                }
            }
        };
        if RECORD_STAGES.load(Ordering::Relaxed) {
            if let Some(path) = STAGES_LOG_PATH.get() {
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true).append(true).open(path)
                {
                    let _ = f.write_all(&[stage_byte]);
                }
            }
        }
        let rss_delta = current_rss_bytes().saturating_sub(rss_before);
        if RECORD_DELTAS.load(Ordering::Relaxed) {
            if let Some(path) = DELTAS_LOG_PATH.get() {
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true).append(true).open(path)
                {
                    let _ = writeln!(f, "{rss_delta}");
                }
            }
        }
        // Report as a crash if this input caused anomalous allocation.
        if rss_delta > RSS_LIMIT.load(Ordering::Relaxed) {
            return ExitKind::Crash;
        }
        ExitKind::Ok
    };

    // Coverage map fed by the sancov trace-pc-guard hooks (see .cargo/config.toml).
    let edges_observer = HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") });
    // Wall-clock time per iteration — feeds TimeFeedback (corpus) and TimeoutFeedback (objective).
    let time_observer = TimeObserver::new("time");
    // Backtrace hash — deduplicates the crash corpus so every finding has a distinct stack.
    let backtrace_observer = BacktraceObserver::owned("backtrace", HarnessType::Child);

    // New edge coverage OR unusually slow inputs keep the input in the corpus.
    let mut feedback = EagerOrFeedback::new(
        MaxMapFeedback::new(&edges_observer),
        TimeFeedback::new(&time_observer),
    );
    // A finding is saved only when it is a crash/timeout AND its backtrace hash is new.
    // This prevents the crashes/ directory from filling with thousands of inputs that all
    // hit the same allocation path.
    let mut objective = EagerOrFeedback::new(
        EagerOrFeedback::new(CrashFeedback::new(), TimeoutFeedback::new()),
        NewHashFeedback::new(&backtrace_observer),
    );

    let mut state = StdState::new(
        StdRand::with_seed(0xC0FFEE),
        OnDiskCorpus::new(&corpus_dir).unwrap(),
        OnDiskCorpus::new(&crashes_dir).unwrap(),
        &mut feedback,
        &mut objective,
    )?;

    let monitor = SimpleMonitor::new(move |s| {
        println!("{s}");
        if record_stages {
            if let Ok(data) = std::fs::read(&stages_log) {
                let total = data.len();
                if total > 0 {
                    let d = data.iter().filter(|&&b| b == b'D').count();
                    let i = data.iter().filter(|&&b| b == b'I').count();
                    let l = data.iter().filter(|&&b| b == b'L').count();
                    let t = data.iter().filter(|&&b| b == b'T').count();
                    eprintln!(
                        "[stages] n={total}  \
                         decode_fail={d} ({:.1}%)  \
                         linkage_fail={i} ({:.1}%)  \
                         loading_fail={l} ({:.1}%)  \
                         typing_reached={t} ({:.1}%)",
                        d as f64 / total as f64 * 100.0,
                        i as f64 / total as f64 * 100.0,
                        l as f64 / total as f64 * 100.0,
                        t as f64 / total as f64 * 100.0,
                    );
                }
            }
        }
    });
    let mut mgr = SimpleEventManager::new(monitor);

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // InProcessForkExecutor forks before each iteration so an OOM kill in the child
    // does not take down the fuzzer.  The parent catches SIGCHLD and records the
    // ExitKind (Crash / Timeout / Ok) without being affected by the child's death.
    let shmem_provider = StdShMemProvider::new()?;
    let mut executor = InProcessForkExecutor::new(
        &mut harness,
        tuple_list!(edges_observer, time_observer, backtrace_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        Duration::from_millis(500),
        shmem_provider,
    )?;

    // Load the BCS-seeded corpus produced by gen_corpus; fall back to a small
    // random batch if the directory is missing or empty.
    if corpus_dir.is_dir() && corpus_dir.read_dir().map_or(false, |mut d| d.next().is_some()) {
        // Force all seeds into the corpus regardless of coverage novelty so the
        // mutator has the full structural diversity of all 10 hand-crafted seeds.
        state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[corpus_dir])?;
    } else {
        use std::num::NonZeroUsize;
        use libafl::generators::RandBytesGenerator;
        let mut generator = RandBytesGenerator::new(NonZeroUsize::new(64).unwrap());
        state.generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 16)?;
    }

    // Two separate stages so they never compose on the same input in the same iteration.
    //
    // Stage 1: SingleChoiceScheduledMutator runs PtbMutator exactly ONCE per corpus
    // entry per fuzzer loop iteration — BCS validity is always preserved.
    //
    // Stage 2: HavocScheduledMutator runs 1–128 havoc mutations for raw-byte diversity.
    // Its decode failures are expected and don't pollute the stage 1 ratio.
    let ptb_stage = StdMutationalStage::new(SingleChoiceScheduledMutator::new(tuple_list!(PtbMutator)));
    let havoc_stage = StdMutationalStage::new(HavocScheduledMutator::new(havoc_mutations()));
    let mut stages = tuple_list!(ptb_stage, havoc_stage);

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    Ok(())
}
