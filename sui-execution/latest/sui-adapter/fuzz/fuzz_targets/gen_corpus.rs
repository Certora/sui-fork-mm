// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Corpus generator for the `translate_and_verify` fuzzing campaign.
//!
//! Produces BCS-serialized `ProgrammableTransaction` files in `./corpus/`.
//! Each file exercises a distinct structural stress case identified from the
//! typing pipeline source. Run once before the fuzzer:
//!
//!   cargo run --bin gen_corpus

use std::{fs, path::Path};

extern crate libc;

#[path = "fixture.rs"]
mod fixture;
use fixture::{Fixture, run_typing};

// The .cargo/config.toml injects sancov rustflags for every binary in this crate.
// gen_corpus doesn't link libafl_targets, so provide no-op stubs for the two
// sancov callbacks that the instrumented code emits.
#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_pc_guard(_guard: *mut u32) {}
#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_pc_guard_init(_start: *mut u32, _stop: *mut u32) {}
#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_pc_indir(_callee: usize) {}

use sui_types::{
    base_types::{ObjectID, SuiAddress},
    transaction::{Argument, Command, ProgrammableMoveCall, ProgrammableTransaction},
    type_input::{StructInput, TypeInput},
    SUI_FRAMEWORK_PACKAGE_ID,
};
use move_core_types::account_address::AccountAddress;

/// Write `ptb` as a BCS file named `corpus/<name>.bin`.
fn write(dir: &Path, name: &str, ptb: ProgrammableTransaction) {
    let bytes = bcs::to_bytes(&ptb).expect("BCS serialization failed");
    let path = dir.join(format!("{name}.bin"));
    fs::write(&path, &bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    println!("wrote {} ({} bytes)", path.display(), bytes.len());
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sui_pkg() -> ObjectID {
    SUI_FRAMEWORK_PACKAGE_ID
}

fn ident(s: &str) -> String {
    s.to_owned()
}

/// `0x2::coin::Coin<0x2::sui::SUI>`
fn sui_coin_type() -> TypeInput {
    TypeInput::Struct(Box::new(StructInput {
        address: AccountAddress::from(SUI_FRAMEWORK_PACKAGE_ID),
        module: ident("coin"),
        name: ident("Coin"),
        type_params: vec![TypeInput::Struct(Box::new(StructInput {
            address: AccountAddress::from(SUI_FRAMEWORK_PACKAGE_ID),
            module: ident("sui"),
            name: ident("SUI"),
            type_params: vec![],
        }))],
    }))
}

/// Build a `TypeInput::Vector(Vector(…(Bool)…))` nested `depth` levels deep.
fn nested_vector(depth: u32) -> TypeInput {
    let mut t = TypeInput::Bool;
    for _ in 0..depth {
        t = TypeInput::Vector(Box::new(t));
    }
    t
}

// ---------------------------------------------------------------------------
// Scenario 1 — Max-command chain of SplitCoins feeding MergeCoins (borrow chain stress)
//
// SplitCoins(GasCoin, [pure_amount]) -> Result(0)
// MergeCoins(GasCoin, [Result(0)])
// SplitCoins(GasCoin, [pure_amount]) -> Result(2)
// MergeCoins(GasCoin, [Result(2)])
// … repeated 512 times (1024 total commands)
//
// What it stresses: the borrow-chain / memory-safety PathSet cloning in
// invariant_checks::memory_safety because each SplitCoins/MergeCoins pair
// extends the reference derivation chain.
// ---------------------------------------------------------------------------
fn split_merge_chain(pairs: usize) -> ProgrammableTransaction {
    let amount_bytes = bcs::to_bytes(&1u64).unwrap();
    let pure_input = Argument::Input(0);

    let mut commands = Vec::with_capacity(pairs * 2);
    for i in 0..pairs {
        let split_result_idx = (i * 2) as u16;
        // SplitCoins(GasCoin, [pure_amount])
        commands.push(Command::SplitCoins(
            Argument::GasCoin,
            vec![pure_input],
        ));
        // MergeCoins(GasCoin, [Result(split_result_idx)])
        commands.push(Command::MergeCoins(
            Argument::GasCoin,
            vec![Argument::Result(split_result_idx)],
        ));
    }

    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(amount_bytes)],
        commands,
    }
}

// ---------------------------------------------------------------------------
// Scenario 2 — MakeMoveVec fan-out: one command, max arguments all pointing
// to the same input
//
// What it stresses: translate::Context argument-splatting and the
// O(#commands × #args) result accumulation in memory_safety.
// ---------------------------------------------------------------------------
fn make_move_vec_fan_out(n_args: usize) -> ProgrammableTransaction {
    let amount_bytes = bcs::to_bytes(&0u64).unwrap();
    // All arguments point to Input(0) — the pure u64
    let args = vec![Argument::Input(0); n_args];
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(amount_bytes)],
        commands: vec![Command::MakeMoveVec(Some(TypeInput::U64), args)],
    }
}

// ---------------------------------------------------------------------------
// Scenario 3 — Many MakeMoveVec commands each pointing back to the previous
// result (linear result-reference chain)
//
// MakeMoveVec(U64, [Input(0)])      -> Result(0)
// MakeMoveVec(vector<U64>, [Result(0)]) -> Result(1)
// MakeMoveVec(vector<vector<U64>>, [Result(1)]) -> Result(2)
// …
//
// What it stresses: Path.extensions chain growth in memory_safety — each step
// adds a Delta to the derivation path of the final result.
// ---------------------------------------------------------------------------
fn deep_result_chain(depth: usize) -> ProgrammableTransaction {
    let val_bytes = bcs::to_bytes(&42u64).unwrap();
    let mut commands = Vec::with_capacity(depth);
    for i in 0..depth {
        let ty = nested_vector(i as u32); // vec<vec<…<U64>…>>
        let arg = if i == 0 {
            Argument::Input(0)
        } else {
            Argument::Result((i - 1) as u16)
        };
        commands.push(Command::MakeMoveVec(Some(ty), vec![arg]));
    }
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(val_bytes)],
        commands,
    }
}

// ---------------------------------------------------------------------------
// Scenario 4 — Max type-argument depth in a MoveCall
//
// Calls `0x2::coin::value<Coin<Coin<…<SUI>…>>>` with max nesting.
// The package doesn't exist in the fixture store, so loading fails — but the
// linkage analysis and type-node counting in the meter still runs.
//
// What it stresses: metering::typing type_node_count on deeply nested types,
// and type_argument_depth validation.
// ---------------------------------------------------------------------------
fn deep_type_args(depth: u32) -> ProgrammableTransaction {
    // Build Coin<Coin<…<SUI>…>>
    let mut inner = TypeInput::Struct(Box::new(StructInput {
        address: AccountAddress::from(SUI_FRAMEWORK_PACKAGE_ID),
        module: ident("sui"),
        name: ident("SUI"),
        type_params: vec![],
    }));
    for _ in 0..depth {
        inner = TypeInput::Struct(Box::new(StructInput {
            address: AccountAddress::from(SUI_FRAMEWORK_PACKAGE_ID),
            module: ident("coin"),
            name: ident("Coin"),
            type_params: vec![inner],
        }));
    }

    ProgrammableTransaction {
        inputs: vec![],
        commands: vec![Command::MoveCall(Box::new(ProgrammableMoveCall {
            package: sui_pkg(),
            module: ident("coin"),
            function: ident("value"),
            type_arguments: vec![inner],
            arguments: vec![],
        }))],
    }
}

// ---------------------------------------------------------------------------
// Scenario 5 — Max type arguments (width) in a MoveCall
//
// Calls with 16 type arguments (the protocol-config maximum).
//
// What it stresses: the per-command type-argument validation loop and
// metering across a wide argument list.
// ---------------------------------------------------------------------------
fn wide_type_args() -> ProgrammableTransaction {
    let type_args: Vec<TypeInput> = (0..16).map(|_| sui_coin_type()).collect();
    ProgrammableTransaction {
        inputs: vec![],
        commands: vec![Command::MoveCall(Box::new(ProgrammableMoveCall {
            package: sui_pkg(),
            module: ident("coin"),
            function: ident("value"),
            type_arguments: type_args,
            arguments: vec![],
        }))],
    }
}

// ---------------------------------------------------------------------------
// Scenario 6 — Pure input at max size (16 KiB), referenced many times
//
// What it stresses: bytes interning (IndexSet growth) and type-inference
// paths that must re-evaluate the same pure input against different expected
// types in different commands.
// ---------------------------------------------------------------------------
fn max_pure_input_multi_use(n_uses: usize) -> ProgrammableTransaction {
    let big_bytes = vec![0xABu8; 16 * 1024 - 1]; // just under 16 KiB limit
    let cmds: Vec<Command> = (0..n_uses)
        .map(|_| Command::MakeMoveVec(Some(TypeInput::U8), vec![Argument::Input(0)]))
        .collect();
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(big_bytes)],
        commands: cmds,
    }
}

// ---------------------------------------------------------------------------
// Scenario 7 — Dense NestedResult cross-references
//
// Many commands, each with NestedResult args pointing back to earlier
// commands at various (cmd, sub) indices.
//
// What it stresses: the out-of-bounds path in translate::Context::locations()
// and NestedResult handling in the typing context.
// ---------------------------------------------------------------------------
fn nested_result_crossref(n_cmds: usize) -> ProgrammableTransaction {
    let val_bytes = bcs::to_bytes(&1u64).unwrap();
    let mut cmds = Vec::with_capacity(n_cmds + 1);
    // Seed: first command produces a result from a pure input.
    cmds.push(Command::MakeMoveVec(
        Some(TypeInput::U64),
        vec![Argument::Input(0)],
    ));
    for i in 1..n_cmds {
        let base = (i - 1) as u16;
        // NestedResult(base_cmd, sub_index=0) — always references sub-index 0
        let args = vec![Argument::NestedResult(base, 0)];
        cmds.push(Command::MakeMoveVec(Some(TypeInput::U64), args));
    }
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(val_bytes)],
        commands: cmds,
    }
}

// ---------------------------------------------------------------------------
// Scenario 8 — TransferObjects with many arguments (fan-in)
//
// Single TransferObjects command collecting 1023 results plus the gas coin.
//
// What it stresses: argument-count validation and memory-safety tracking of
// many-input commands.
// ---------------------------------------------------------------------------
fn transfer_fan_in(n: usize) -> ProgrammableTransaction {
    let amount_bytes = bcs::to_bytes(&1u64).unwrap();
    let recipient_bytes = bcs::to_bytes(&SuiAddress::ZERO).unwrap();

    // Produce n SplitCoins results
    let mut cmds: Vec<Command> = (0..n)
        .map(|_| Command::SplitCoins(Argument::GasCoin, vec![Argument::Input(0)]))
        .collect();

    let args: Vec<Argument> = (0..n).map(|i| Argument::Result(i as u16)).collect();
    cmds.push(Command::TransferObjects(args, Argument::Input(1)));

    ProgrammableTransaction {
        inputs: vec![
            sui_types::transaction::CallArg::Pure(amount_bytes),
            sui_types::transaction::CallArg::Pure(recipient_bytes),
        ],
        commands: cmds,
    }
}

// ---------------------------------------------------------------------------
// Scenario 9 — Minimal valid PTB (regression baseline)
//
// Single TransferObjects of GasCoin to address zero. Expected to pass all
// typing checks — useful as a baseline to confirm the fixture works.
// ---------------------------------------------------------------------------
fn minimal_transfer() -> ProgrammableTransaction {
    let recipient_bytes = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(recipient_bytes)],
        commands: vec![Command::TransferObjects(
            vec![Argument::GasCoin],
            Argument::Input(0),
        )],
    }
}

// ---------------------------------------------------------------------------
// Scenario 11 — SplitCoins with many amounts in one command → many NestedResults
//
// SplitCoins(GasCoin, [amt]*N) produces N sub-results accessed via NestedResult.
// None of the original 10 seeds exercise NestedResult(cmd, sub_idx > 0).
//
// What it stresses: multi-return result sub-index handling in translate::Context,
// NestedResult bounds checking, and the result-type accumulation for wide outputs.
// ---------------------------------------------------------------------------
fn split_many_amounts(n: usize) -> ProgrammableTransaction {
    let amt = bcs::to_bytes(&1u64).unwrap();
    let amounts = vec![Argument::Input(0); n];
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(amt)],
        commands: vec![Command::SplitCoins(Argument::GasCoin, amounts)],
    }
}

// ---------------------------------------------------------------------------
// Scenario 12 — NestedResult fan-in: split gas into N sub-results, collect
// them all into TransferObjects via NestedResult(0, i) references
//
// What it stresses: NestedResult sub-index validation across a wide range,
// the borrow-tracking of many independently derived coin references, and
// the TransferObjects many-argument path.
// ---------------------------------------------------------------------------
fn nested_result_fan_in(n: usize) -> ProgrammableTransaction {
    let amt = bcs::to_bytes(&1u64).unwrap();
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();

    let amounts = vec![Argument::Input(0); n];
    let split_cmd = Command::SplitCoins(Argument::GasCoin, amounts);

    let objects: Vec<Argument> = (0..n).map(|i| Argument::NestedResult(0, i as u16)).collect();
    let transfer_cmd = Command::TransferObjects(objects, Argument::Input(1));

    ProgrammableTransaction {
        inputs: vec![
            sui_types::transaction::CallArg::Pure(amt),
            sui_types::transaction::CallArg::Pure(addr),
        ],
        commands: vec![split_cmd, transfer_cmd],
    }
}

// ---------------------------------------------------------------------------
// Scenario 13 — Deep SplitCoins tree: each split result is split again
//
// SplitCoins(GasCoin, [amt])  → R(0)
// SplitCoins(R(0), [amt])     → R(1)
// SplitCoins(R(1), [amt])     → R(2)
// ...
//
// What it stresses: chained mutable-borrow derivation through the coin type;
// each split consumes the previous result, exercising the linear-borrow
// tracking in memory_safety.
// ---------------------------------------------------------------------------
fn split_chain(depth: usize) -> ProgrammableTransaction {
    let amt = bcs::to_bytes(&1u64).unwrap();
    let mut cmds = Vec::with_capacity(depth);
    for i in 0..depth {
        let src = if i == 0 { Argument::GasCoin } else { Argument::Result((i - 1) as u16) };
        cmds.push(Command::SplitCoins(src, vec![Argument::Input(0)]));
    }
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(amt)],
        commands: cmds,
    }
}

// ---------------------------------------------------------------------------
// Scenario 14 — MakeMoveVec of primitive types (Bool, U8, Address)
//
// Uses only pure inputs and primitive TypeInput variants — zero package
// resolution required.  Three separate commands exercise different primitive
// type paths through the type-inference code.
//
// What it stresses: primitive type unification in translate::Context,
// pure-input interning across different expected types.
// ---------------------------------------------------------------------------
fn make_vec_primitives() -> ProgrammableTransaction {
    let bool_bytes  = bcs::to_bytes(&true).unwrap();
    let u8_bytes    = bcs::to_bytes(&42u8).unwrap();
    let addr_bytes  = bcs::to_bytes(&SuiAddress::ZERO).unwrap();

    ProgrammableTransaction {
        inputs: vec![
            sui_types::transaction::CallArg::Pure(bool_bytes),
            sui_types::transaction::CallArg::Pure(u8_bytes),
            sui_types::transaction::CallArg::Pure(addr_bytes),
        ],
        commands: vec![
            Command::MakeMoveVec(Some(TypeInput::Bool),    vec![Argument::Input(0); 32]),
            Command::MakeMoveVec(Some(TypeInput::U8),      vec![Argument::Input(1); 32]),
            Command::MakeMoveVec(Some(TypeInput::Address), vec![Argument::Input(2); 32]),
        ],
    }
}

// ---------------------------------------------------------------------------
// Scenario 15 — Merge-then-split-then-merge: exercises the full borrow cycle
//
// SplitCoins(GasCoin, [a, b, c])   → sub-results 0,1,2
// MergeCoins(GasCoin, [NR(0,0), NR(0,1)])
// SplitCoins(GasCoin, [a])         → R(2)
// MergeCoins(GasCoin, [NR(0,2), R(2)])
//
// What it stresses: interleaved split/merge operations on NestedResult and
// Result references; the memory_safety pass tracking coins that are merged
// then re-split, testing path convergence in the borrow graph.
// ---------------------------------------------------------------------------
fn merge_split_cycle() -> ProgrammableTransaction {
    let amt = bcs::to_bytes(&1u64).unwrap();
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(amt)],
        commands: vec![
            // SplitCoins(GasCoin, [amt, amt, amt]) → NR(0,0), NR(0,1), NR(0,2)
            Command::SplitCoins(Argument::GasCoin, vec![
                Argument::Input(0),
                Argument::Input(0),
                Argument::Input(0),
            ]),
            // MergeCoins(GasCoin, [NR(0,0), NR(0,1)])
            Command::MergeCoins(Argument::GasCoin, vec![
                Argument::NestedResult(0, 0),
                Argument::NestedResult(0, 1),
            ]),
            // SplitCoins(GasCoin, [amt]) → R(2)
            Command::SplitCoins(Argument::GasCoin, vec![Argument::Input(0)]),
            // MergeCoins(GasCoin, [NR(0,2), R(2)])
            Command::MergeCoins(Argument::GasCoin, vec![
                Argument::NestedResult(0, 2),
                Argument::Result(2),
            ]),
        ],
    }
}

// ---------------------------------------------------------------------------
// Scenario 16 — Max-width SplitCoins (255 sub-results) + max NestedResult index
//
// SplitCoins(GasCoin, [amt]*255) → 255 sub-results (NestedResult(0, 0..254))
// TransferObjects([NR(0,0), NR(0,254)], addr)  — tests boundary sub-indices
//
// What it stresses: maximum sub-result index validation (u16 boundary near
// 255), the result-type Vec capacity for wide single commands.
// ---------------------------------------------------------------------------
fn split_max_width_boundary() -> ProgrammableTransaction {
    let amt  = bcs::to_bytes(&1u64).unwrap();
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    let amounts = vec![Argument::Input(0); 255];
    ProgrammableTransaction {
        inputs: vec![
            sui_types::transaction::CallArg::Pure(amt),
            sui_types::transaction::CallArg::Pure(addr),
        ],
        commands: vec![
            Command::SplitCoins(Argument::GasCoin, amounts),
            Command::TransferObjects(
                vec![Argument::NestedResult(0, 0), Argument::NestedResult(0, 254)],
                Argument::Input(1),
            ),
        ],
    }
}

// ---------------------------------------------------------------------------
// Scenario 10 — Empty PTB (edge case: zero commands)
// ---------------------------------------------------------------------------
fn empty_ptb() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![],
        commands: vec![],
    }
}

/// Returns current process RSS in bytes by reading `VmRSS` from `/proc/self/status`.
/// Unlike `getrusage(RUSAGE_SELF).ru_maxrss` (which is a peak-ever value on Linux),
/// this reflects the live working-set size and produces a meaningful delta.
fn current_rss_bytes() -> u64 {
    fs::read_to_string("/proc/self/status")
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

fn main() {
    let dir = Path::new("corpus");
    fs::create_dir_all(dir).expect("failed to create corpus/");

    write(dir, "01_minimal_transfer", minimal_transfer());
    write(dir, "02_empty_ptb", empty_ptb());
    write(dir, "03_split_merge_chain_512", split_merge_chain(512));
    write(dir, "04_make_move_vec_fan_out_255", make_move_vec_fan_out(255));
    write(dir, "05_deep_result_chain_64", deep_result_chain(64));
    write(dir, "06_deep_type_args_16", deep_type_args(16));
    write(dir, "07_wide_type_args_16", wide_type_args());
    write(dir, "08_max_pure_multi_use_64", max_pure_input_multi_use(64));
    write(dir, "09_nested_result_crossref_512", nested_result_crossref(512));
    write(dir, "10_transfer_fan_in_255", transfer_fan_in(255));
    write(dir, "11_split_many_amounts_255", split_many_amounts(255));
    write(dir, "12_nested_result_fan_in_64", nested_result_fan_in(64));
    write(dir, "13_split_chain_256", split_chain(256));
    write(dir, "14_make_vec_primitives", make_vec_primitives());
    write(dir, "15_merge_split_cycle", merge_split_cycle());
    write(dir, "16_split_max_width_boundary", split_max_width_boundary());

    println!("\nCorpus ready in ./corpus/\n");

    // ── Calibration ──────────────────────────────────────────────────────────
    // Run each corpus file through the real typing pipeline and measure the RSS
    // delta.  This gives an empirical baseline for RSS_DELTA_LIMIT_BYTES in the
    // fuzzer harness rather than an arbitrary guess.
    println!("Calibrating RSS delta per corpus file (building fixture — may take a moment)...\n");

    let fixture = Fixture::new();

    let mut entries: Vec<(String, u64)> = fs::read_dir(dir)
        .expect("failed to read corpus/")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |x| x == "bin"))
        .map(|e| {
            let path = e.path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let bytes = fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));

            let rss_before = current_rss_bytes();
            if let Ok(ptb) = bcs::from_bytes::<sui_types::transaction::ProgrammableTransaction>(&bytes) {
                let (_, _) = run_typing(&fixture, ptb);
            }
            let delta = current_rss_bytes().saturating_sub(rss_before);
            (name, delta)
        })
        .collect();

    entries.sort_by_key(|(name, _)| name.clone());

    println!("{:<45} {:>12}", "file", "RSS delta");
    println!("{}", "-".repeat(59));
    let mut max_delta: u64 = 0;
    for (name, delta) in &entries {
        println!("{:<45} {:>9} KiB", name, delta / 1024);
        max_delta = max_delta.max(*delta);
    }

    // 5× the observed maximum, rounded up to the nearest MiB, floored at 1 MiB.
    //
    // Why 5×: the seeds are already hand-crafted worst cases.  A legitimate fuzz
    // mutation of the worst seed is unlikely to allocate more than a few multiples
    // of it, so 5× leaves enough headroom to avoid false positives while still
    // catching genuinely pathological inputs well below an arbitrary ceiling.
    //
    // This number is only a starting point.  After a warm-up run of ~10 minutes,
    // re-calibrate by plotting the actual RSS-delta distribution across all
    // inputs that reached run_typing and tighten the threshold to e.g. the
    // 99.9th percentile plus one multiplier step.
    let suggested = (max_delta * 5).max(1024 * 1024);
    let suggested_mib = suggested.div_ceil(1024 * 1024);
    println!();
    println!("Max observed delta : {} KiB", max_delta / 1024);
    println!("Suggested RSS_DELTA_LIMIT_BYTES: {suggested_mib} MiB  ({suggested} bytes)");
    println!();
    println!(
        "This is a seed-based estimate (5× worst seed).  Re-calibrate after a \
         ~10-minute warm-up run using the actual RSS-delta distribution."
    );
}
