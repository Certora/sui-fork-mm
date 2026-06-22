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

use tikv_jemalloc_ctl::{epoch, stats};

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[path = "fixture.rs"]
mod fixture;
use fixture::{
    fuzz_fixture::{key_box_type, move_call as fixture_call},
    Fixture, FuzzHarnessObjectRefs, PipelineStage, build_fuzz_harness_objects, run_typing,
};

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
    error::ExecutionErrorTrait,
    execution_status::ExecutionFailure,
    transaction::{Argument, Command, ProgrammableMoveCall, ProgrammableTransaction},
    type_input::{StructInput, TypeInput},
    MOVE_STDLIB_PACKAGE_ID, SUI_FRAMEWORK_PACKAGE_ID,
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

/// `0x1` — the move-stdlib package present in the framework-only fixture store.
fn stdlib_pkg() -> ObjectID {
    MOVE_STDLIB_PACKAGE_ID
}

/// Build a `MoveCall` command against a framework package.
fn move_call(
    package: ObjectID,
    module: &str,
    function: &str,
    type_arguments: Vec<TypeInput>,
    arguments: Vec<Argument>,
) -> Command {
    Command::MoveCall(Box::new(ProgrammableMoveCall {
        package,
        module: ident(module),
        function: ident(function),
        type_arguments,
        arguments,
    }))
}

/// 32 little-endian bytes — the BCS encoding of a `u256` value (the concrete
/// value is irrelevant; typing only checks the byte length against the type).
fn u256_bytes() -> Vec<u8> {
    vec![0u8; 32]
}

fn ident(s: &str) -> String {
    s.to_owned()
}

/// `0x2::sui::SUI`
fn sui_type() -> TypeInput {
    TypeInput::Struct(Box::new(StructInput {
        address: AccountAddress::from(SUI_FRAMEWORK_PACKAGE_ID),
        module: ident("sui"),
        name: ident("SUI"),
        type_params: vec![],
    }))
}

/// `0x2::coin::Coin<0x2::sui::SUI>`
fn sui_coin_type() -> TypeInput {
    TypeInput::Struct(Box::new(StructInput {
        address: AccountAddress::from(SUI_FRAMEWORK_PACKAGE_ID),
        module: ident("coin"),
        name: ident("Coin"),
        type_params: vec![sui_type()],
    }))
}

/// Build a `TypeInput::Vector(Vector(…(U64)…))` nested `depth` levels deep.
/// `depth == 0` yields `U64`, matching a `u64` pure input at the base of the chain.
fn nested_vector(depth: u32) -> TypeInput {
    let mut t = TypeInput::U64;
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
// Scenario 6 — Pure input at max size (~16 KiB), referenced many times
//
// A single near-16-KiB pure input (a BCS-encoded `vector<u8>`) is consumed by
// `n_uses` `MakeMoveVec<vector<u8>>` commands. `vector<u8>` is copyable, so the
// same input can be referenced by every command, and the resulting
// `vector<vector<u8>>` is droppable, so the results need not be consumed.
//
// What it stresses: bytes interning (IndexSet growth) and the type-inference
// path that re-evaluates the same large pure input against the same expected
// type across many commands.
// ---------------------------------------------------------------------------
fn max_pure_input_multi_use(n_uses: usize) -> ProgrammableTransaction {
    // BCS-encode a Vec<u8> so the pure input is a valid `vector<u8>` value.
    // The ULEB128 length prefix adds a few bytes, so leave headroom under 16 KiB.
    let payload = vec![0xABu8; 16 * 1024 - 16];
    let big_bytes = bcs::to_bytes(&payload).unwrap();
    let elem_ty = TypeInput::Vector(Box::new(TypeInput::U8));
    let cmds: Vec<Command> = (0..n_uses)
        .map(|_| Command::MakeMoveVec(Some(elem_ty.clone()), vec![Argument::Input(0)]))
        .collect();
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(big_bytes)],
        commands: cmds,
    }
}

// ---------------------------------------------------------------------------
// Scenario 7 — Dense NestedResult references to a single source command
//
// Command 0 produces a `vector<U64>`; every subsequent command wraps it again
// via `NestedResult(0, 0)`, producing `vector<vector<U64>>`. Referencing
// command 0 (rather than chaining through each previous command) keeps the
// result type bounded — a chained version would nest the vector type `n_cmds`
// levels deep and exceed the type-depth limit. `vector<U64>` is copyable, so the
// same sub-result feeds every command, and the droppable results need no
// consumer.
//
// What it stresses: NestedResult sub-index resolution in translate::Context
// repeated across many commands referencing the same source.
// ---------------------------------------------------------------------------
fn nested_result_crossref(n_cmds: usize) -> ProgrammableTransaction {
    let val_bytes = bcs::to_bytes(&1u64).unwrap();
    let mut cmds = Vec::with_capacity(n_cmds);
    // Seed: first command produces a `vector<U64>` from a pure input.
    cmds.push(Command::MakeMoveVec(
        Some(TypeInput::U64),
        vec![Argument::Input(0)],
    ));
    let wrap_ty = TypeInput::Vector(Box::new(TypeInput::U64));
    for _ in 1..n_cmds {
        // Reference command 0's single return value via NestedResult(0, 0).
        let args = vec![Argument::NestedResult(0, 0)];
        cmds.push(Command::MakeMoveVec(Some(wrap_ty.clone()), args));
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
// Scenario 10 — Empty PTB (edge case: zero commands)
// ---------------------------------------------------------------------------
fn empty_ptb() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![],
        commands: vec![],
    }
}

// ---------------------------------------------------------------------------
// Scenario 11 — SplitCoins with many amounts in one command → many NestedResults
//
// SplitCoins(GasCoin, [amt]*N) produces N sub-results accessed via NestedResult.
// All N coins are then transferred so the (non-droppable) coins are consumed.
//
// What it stresses: multi-return result sub-index handling in translate::Context,
// NestedResult bounds checking, and the result-type accumulation for wide outputs.
// ---------------------------------------------------------------------------
fn split_many_amounts(n: usize) -> ProgrammableTransaction {
    let amt = bcs::to_bytes(&1u64).unwrap();
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    let amounts = vec![Argument::Input(0); n];
    let objects: Vec<Argument> = (0..n).map(|i| Argument::NestedResult(0, i as u16)).collect();
    ProgrammableTransaction {
        inputs: vec![
            sui_types::transaction::CallArg::Pure(amt),
            sui_types::transaction::CallArg::Pure(addr),
        ],
        commands: vec![
            Command::SplitCoins(Argument::GasCoin, amounts),
            Command::TransferObjects(objects, Argument::Input(1)),
        ],
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
// each split derives from the previous result, exercising the linear-borrow
// tracking in memory_safety. All `depth` derived coins are transferred at the
// end so the non-droppable coins are consumed.
// ---------------------------------------------------------------------------
fn split_chain(depth: usize) -> ProgrammableTransaction {
    let amt = bcs::to_bytes(&1u64).unwrap();
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    let mut cmds = Vec::with_capacity(depth + 1);
    for i in 0..depth {
        let src = if i == 0 { Argument::GasCoin } else { Argument::Result((i - 1) as u16) };
        cmds.push(Command::SplitCoins(src, vec![Argument::Input(0)]));
    }
    let objects: Vec<Argument> = (0..depth).map(|i| Argument::Result(i as u16)).collect();
    cmds.push(Command::TransferObjects(objects, Argument::Input(1)));
    ProgrammableTransaction {
        inputs: vec![
            sui_types::transaction::CallArg::Pure(amt),
            sui_types::transaction::CallArg::Pure(addr),
        ],
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
// TransferObjects([NR(0,0)..NR(0,254)], addr) — consumes every coin, spanning
// the boundary sub-indices 0 and 254.
//
// What it stresses: maximum sub-result index validation (u16 boundary near
// 255), the result-type Vec capacity for wide single commands.
// ---------------------------------------------------------------------------
fn split_max_width_boundary() -> ProgrammableTransaction {
    let amt  = bcs::to_bytes(&1u64).unwrap();
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    let amounts = vec![Argument::Input(0); 255];
    let objects: Vec<Argument> = (0..255).map(|i| Argument::NestedResult(0, i as u16)).collect();
    ProgrammableTransaction {
        inputs: vec![
            sui_types::transaction::CallArg::Pure(amt),
            sui_types::transaction::CallArg::Pure(addr),
        ],
        commands: vec![
            Command::SplitCoins(Argument::GasCoin, amounts),
            Command::TransferObjects(objects, Argument::Input(1)),
        ],
    }
}

// ---------------------------------------------------------------------------
// Scenario 17 — Valid MoveCall with no arguments and no type arguments
//
// `0x2::address::length(): u64`. The result is a droppable primitive left
// unconsumed.
//
// What it stresses: the MoveCall loading + typing path itself. Every other
// Typing-OK seed uses only the built-in commands (Split/Merge/Transfer/
// MakeMoveVec); this is the first seed that drives a real framework function
// signature all the way through `translate_and_verify`.
// ---------------------------------------------------------------------------
fn move_call_no_args() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![],
        commands: vec![move_call(sui_pkg(), "address", "length", vec![], vec![])],
    }
}

// ---------------------------------------------------------------------------
// Scenario 18 — MoveCall taking a single pure primitive argument
//
// `0x2::address::from_u256(n: u256): address`. A pure `u256` input is bound to
// the by-value primitive parameter; the `address` result is droppable.
//
// What it stresses: pure-input → primitive-parameter binding and type
// inference inside a MoveCall (a pure input resolved against a function
// signature rather than a built-in command's expected type).
// ---------------------------------------------------------------------------
fn move_call_pure_primitive() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(u256_bytes())],
        commands: vec![move_call(
            sui_pkg(),
            "address",
            "from_u256",
            vec![],
            vec![Argument::Input(0)],
        )],
    }
}

// ---------------------------------------------------------------------------
// Scenario 19 — MoveCall taking a pure `vector<u8>` argument
//
// `0x1::ascii::string(bytes: vector<u8>): ascii::String`. The pure input is a
// BCS-encoded `vector<u8>`; the returned `String` is droppable.
//
// What it stresses: pure-input → `vector<u8>` parameter binding through a
// MoveCall, and resolving a framework struct (`ascii::String`) as a result
// type.
// ---------------------------------------------------------------------------
fn move_call_vector_arg() -> ProgrammableTransaction {
    let bytes = bcs::to_bytes(&vec![0x41u8, 0x42, 0x43]).unwrap();
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(bytes)],
        commands: vec![move_call(
            stdlib_pkg(),
            "ascii",
            "string",
            vec![],
            vec![Argument::Input(0)],
        )],
    }
}

// ---------------------------------------------------------------------------
// Scenario 20 — MoveCall with a generic type argument and no value arguments
//
// `0x1::type_name::get<T>(): TypeName` with `T = 0x2::coin::Coin<0x2::sui::SUI>`.
// The returned `TypeName` is droppable.
//
// What it stresses: generic type-argument substitution / resolution in the
// loading + typing passes when there are no value arguments to constrain it.
// ---------------------------------------------------------------------------
fn move_call_generic_type_arg() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![],
        commands: vec![move_call(
            stdlib_pkg(),
            "type_name",
            "get",
            vec![sui_coin_type()],
            vec![],
        )],
    }
}

// ---------------------------------------------------------------------------
// Scenario 21 — MoveCall taking an immutable-reference argument
//
// `0x2::hash::keccak256(data: &vector<u8>): vector<u8>`. The pure input is
// passed by immutable reference; the `vector<u8>` result is droppable.
//
// What it stresses: borrow inference for a pure input fed to a `&T` parameter
// — a distinct typing path from by-value argument binding.
// ---------------------------------------------------------------------------
fn move_call_reference_arg() -> ProgrammableTransaction {
    let bytes = bcs::to_bytes(&vec![0u8; 64]).unwrap();
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(bytes)],
        commands: vec![move_call(
            sui_pkg(),
            "hash",
            "keccak256",
            vec![],
            vec![Argument::Input(0)],
        )],
    }
}

// ---------------------------------------------------------------------------
// Scenario 22 — Chain of MoveCalls threading each result into the next
//
// from_u256(Input) → address; to_u256(R0) → u256; from_u256(R1) → address; …
// alternating `depth` times. The final result is a droppable primitive.
//
// What it stresses: result-type propagation across many MoveCalls — each
// command's typed return value becomes the next command's argument, exercising
// the MoveCall result-resolution path repeatedly.
// ---------------------------------------------------------------------------
fn move_call_result_chain(depth: usize) -> ProgrammableTransaction {
    let mut cmds = Vec::with_capacity(depth);
    cmds.push(move_call(
        sui_pkg(),
        "address",
        "from_u256",
        vec![],
        vec![Argument::Input(0)],
    ));
    for i in 1..depth {
        let prev = Argument::Result((i - 1) as u16);
        // Odd steps consume an `address` (→ u256); even steps consume a `u256`
        // (→ address), so the argument type always matches the callee.
        let func = if i % 2 == 1 { "to_u256" } else { "from_u256" };
        cmds.push(move_call(sui_pkg(), "address", func, vec![], vec![prev]));
    }
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(u256_bytes())],
        commands: cmds,
    }
}

// ---------------------------------------------------------------------------
// Scenario 23 — MoveCall results collected into a typed MakeMoveVec
//
// `n` `from_u256` calls each produce an `address`; a final
// `MakeMoveVec<address>([R0..Rn])` collects them. The resulting
// `vector<address>` is droppable.
//
// What it stresses: feeding MoveCall results into a built-in command's
// argument list, and result-type accumulation across a wide MakeMoveVec whose
// elements come from MoveCalls rather than pure inputs.
// ---------------------------------------------------------------------------
fn move_call_make_vec_of_results(n: usize) -> ProgrammableTransaction {
    let mut cmds: Vec<Command> = (0..n)
        .map(|_| {
            move_call(
                sui_pkg(),
                "address",
                "from_u256",
                vec![],
                vec![Argument::Input(0)],
            )
        })
        .collect();
    let elems: Vec<Argument> = (0..n).map(|i| Argument::Result(i as u16)).collect();
    cmds.push(Command::MakeMoveVec(Some(TypeInput::Address), elems));
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(u256_bytes())],
        commands: cmds,
    }
}

// ---------------------------------------------------------------------------
// Scenario 24 — MakeMoveVec with inferred element type (None)
//
// Two `from_u256` calls produce `address` results; `MakeMoveVec(None, [R0, R1])`
// then asks typing to infer the element type from its arguments.
//
// What it stresses: the element-type *inference* branch of MakeMoveVec typing,
// which the explicit-`Some(ty)` seeds never reach. This seed deliberately
// reaches the target with an expected `Err` (not OK): with no annotation,
// MakeMoveVec requires every argument to be the *same object type* (a type with
// `key`), and `address` is not an object — so it exercises both the inference
// branch and its object-type validation/error path inside
// `translate_and_verify`. A would-be valid version (a vector of `Coin<SUI>`)
// can't be expressed here because no built-in command can consume the resulting
// non-droppable `vector<Coin>`.
// ---------------------------------------------------------------------------
fn make_move_vec_none_infer() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(u256_bytes())],
        commands: vec![
            move_call(
                sui_pkg(),
                "address",
                "from_u256",
                vec![],
                vec![Argument::Input(0)],
            ),
            move_call(
                sui_pkg(),
                "address",
                "from_u256",
                vec![],
                vec![Argument::Input(0)],
            ),
            Command::MakeMoveVec(None, vec![Argument::Result(0), Argument::Result(1)]),
        ],
    }
}

// ---------------------------------------------------------------------------
// Scenario 25 — Empty typed MakeMoveVec (zero elements)
//
// `MakeMoveVec<u64>([])` produces an empty `vector<u64>`, which is droppable.
//
// What it stresses: the zero-argument branch of MakeMoveVec typing, where the
// element type comes entirely from the explicit annotation with nothing to
// unify against.
// ---------------------------------------------------------------------------
fn make_move_vec_empty_typed() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![],
        commands: vec![Command::MakeMoveVec(Some(TypeInput::U64), vec![])],
    }
}

// ---------------------------------------------------------------------------
// Scenarios 26–32 — Calls into the synthetic fuzz-fixture package
//
// Unlike the framework `MoveCall` seeds, these target a purpose-built package
// (see `fuzz_fixture.rs`) whose functions span primitives, vectors, references,
// generics with ability bounds, structs, and multiple returns. They drive the
// MoveCall typing path through a controllable, resolvable target.
// ---------------------------------------------------------------------------

// Scenario 26 — fixture call with no arguments or type arguments (`nothing()`).
fn fixture_no_args() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![],
        commands: vec![fixture_call("nothing", vec![], vec![])],
    }
}

// Scenario 27 — fixture call taking a pure primitive (`take_u64(u64)`).
fn fixture_take_primitive() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(
            bcs::to_bytes(&7u64).unwrap(),
        )],
        commands: vec![fixture_call("take_u64", vec![], vec![Argument::Input(0)])],
    }
}

// Scenario 28 — struct round-trip: `new_box(u64) -> Box`, then `unbox(Box) -> u64`.
// Exercises a user-defined struct flowing as a MoveCall result into another call.
fn fixture_struct_roundtrip() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(
            bcs::to_bytes(&1u64).unwrap(),
        )],
        commands: vec![
            fixture_call("new_box", vec![], vec![Argument::Input(0)]),
            fixture_call("unbox", vec![], vec![Argument::Result(0)]),
        ],
    }
}

// Scenario 29 — generic identity (`identity<u64>(u64) -> u64`).
// Exercises generic substitution where the type argument is fixed and a pure
// input must unify against the type parameter.
fn fixture_generic_identity() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(
            bcs::to_bytes(&123u64).unwrap(),
        )],
        commands: vec![fixture_call(
            "identity",
            vec![TypeInput::U64],
            vec![Argument::Input(0)],
        )],
    }
}

// Scenario 30 — multiple-return MoveCall consumed via NestedResult.
// `two_values() -> (u64, bool)`, then each component is fed into a separate call.
fn fixture_multi_return() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![],
        commands: vec![
            fixture_call("two_values", vec![], vec![]),
            fixture_call("take_u64", vec![], vec![Argument::NestedResult(0, 0)]),
            fixture_call("take_bool", vec![], vec![Argument::NestedResult(0, 1)]),
        ],
    }
}

// Scenario 31 — generic struct constructor with ability bounds
// (`make_pair<u64>(u64, u64) -> Pair<u64>`). The copyable pure input is reused
// for both arguments; the droppable `Pair<u64>` result is left unconsumed.
fn fixture_make_pair() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(
            bcs::to_bytes(&9u64).unwrap(),
        )],
        commands: vec![fixture_call(
            "make_pair",
            vec![TypeInput::U64],
            vec![Argument::Input(0), Argument::Input(0)],
        )],
    }
}

// Scenario 32 — immutable-reference parameter (`use_imm_ref(&u64) -> u64`).
// Exercises borrow inference for a pure input passed to a user function's `&T`.
fn fixture_reference_arg() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(
            bcs::to_bytes(&5u64).unwrap(),
        )],
        commands: vec![fixture_call("use_imm_ref", vec![], vec![Argument::Input(0)])],
    }
}

// ---------------------------------------------------------------------------
// Scenario 33 — SplitCoins on an owned coin object input (not GasCoin)
//
// What it stresses: `CallArg::Object(ImmOrOwnedObject)` loading, owned-object
// memory-safety tracking, and SplitCoins on a non-gas coin argument.
// ---------------------------------------------------------------------------
fn split_owned_coin(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    let amt = bcs::to_bytes(&1u64).unwrap();
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    ProgrammableTransaction {
        inputs: vec![
            refs.owned_coin_input(),
            sui_types::transaction::CallArg::Pure(amt),
            sui_types::transaction::CallArg::Pure(addr),
        ],
        commands: vec![
            Command::SplitCoins(Argument::Input(0), vec![Argument::Input(1)]),
            Command::TransferObjects(vec![Argument::NestedResult(0, 0)], Argument::Input(2)),
        ],
    }
}

// ---------------------------------------------------------------------------
// Scenario 34 — MergeCoins across two owned coin object inputs
//
// What it stresses: multiple object inputs, MergeCoins fan-in, and consuming
// two distinct owned objects in one command.
// ---------------------------------------------------------------------------
fn merge_two_owned_coins(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    ProgrammableTransaction {
        inputs: vec![
            refs.owned_coin_input(),
            refs.second_owned_coin_input(),
            sui_types::transaction::CallArg::Pure(addr),
        ],
        commands: vec![
            Command::MergeCoins(Argument::Input(0), vec![Argument::Input(1)]),
            Command::TransferObjects(vec![Argument::Input(0)], Argument::Input(2)),
        ],
    }
}

// ---------------------------------------------------------------------------
// Scenario 35 — TransferObjects of an owned coin object input
//
// What it stresses: object input typed as `Coin<SUI>` flowing directly into
// TransferObjects without an intermediate builtin command.
// ---------------------------------------------------------------------------
fn transfer_owned_coin(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    ProgrammableTransaction {
        inputs: vec![
            refs.owned_coin_input(),
            sui_types::transaction::CallArg::Pure(addr),
        ],
        commands: vec![Command::TransferObjects(
            vec![Argument::Input(0)],
            Argument::Input(1),
        )],
    }
}

// ---------------------------------------------------------------------------
// Scenario 36 — SplitCoins on a mutable shared coin object input
//
// What it stresses: `ObjectArg::SharedObject` loading, consensus-object
// permissions, and SplitCoins on a shared (non-gas) coin.
// ---------------------------------------------------------------------------
fn split_shared_coin(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    let amt = bcs::to_bytes(&1u64).unwrap();
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    ProgrammableTransaction {
        inputs: vec![
            refs.shared_coin_mut_input(),
            sui_types::transaction::CallArg::Pure(amt),
            sui_types::transaction::CallArg::Pure(addr),
        ],
        commands: vec![
            Command::SplitCoins(Argument::Input(0), vec![Argument::Input(1)]),
            Command::TransferObjects(vec![Argument::NestedResult(0, 0)], Argument::Input(2)),
        ],
    }
}

// ---------------------------------------------------------------------------
// Scenario 37 — MoveCall taking an immutable coin object by reference
//
// `0x2::coin::value<T>(c: &Coin<T>)` with an immutable coin object input.
// What it stresses: immutable-object permissions and MoveCall argument binding
// for `&T` parameters backed by a real on-chain object (not a pure input).
// ---------------------------------------------------------------------------
fn move_call_immutable_coin_ref(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![refs.immutable_coin_input()],
        commands: vec![move_call(
            sui_pkg(),
            "coin",
            "value",
            vec![sui_type()],
            vec![Argument::Input(0)],
        )],
    }
}

// ---------------------------------------------------------------------------
// Scenario 38 — MoveCall on an owned coin object (`coin::value`)
//
// Same as scenario 37 but with a mutable owned coin, exercising the owned-
// object borrow path for MoveCall reference parameters.
// ---------------------------------------------------------------------------
fn move_call_owned_coin_ref(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![refs.owned_coin_input()],
        commands: vec![move_call(
            sui_pkg(),
            "coin",
            "value",
            vec![sui_type()],
            vec![Argument::Input(0)],
        )],
    }
}

// ---------------------------------------------------------------------------
// Scenario 39 — TransferObjects of a non-coin `key` object (`KeyBox`)
//
// What it stresses: object-input loading for a user-defined `key` struct (not
// `Coin<SUI>`), plus `TransferObjects` on a non-droppable-by-default type.
// ---------------------------------------------------------------------------
fn transfer_key_box_object(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    ProgrammableTransaction {
        inputs: vec![
            refs.parent_key_box_input(),
            sui_types::transaction::CallArg::Pure(addr),
        ],
        commands: vec![Command::TransferObjects(
            vec![Argument::Input(0)],
            Argument::Input(1),
        )],
    }
}

// ---------------------------------------------------------------------------
// Scenario 40 — MoveCall taking a `KeyBox` object by value
//
// What it stresses: non-coin object consumption in a user-module MoveCall.
// ---------------------------------------------------------------------------
fn move_call_key_box_by_value(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![refs.parent_key_box_input()],
        commands: vec![fixture_call("take_key_box", vec![], vec![Argument::Input(0)])],
    }
}

// ---------------------------------------------------------------------------
// Scenario 41 — MoveCall taking `&KeyBox` (immutable borrow of object input)
// ---------------------------------------------------------------------------
fn move_call_key_box_ref(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![refs.parent_key_box_input()],
        commands: vec![fixture_call("key_box_value", vec![], vec![Argument::Input(0)])],
    }
}

// ---------------------------------------------------------------------------
// Scenario 42 — `Receiving<Coin<SUI>>` resolved via `transfer::public_receive`
//
// Parent `KeyBox` (owned) + receiving coin (address-owned by parent ID).
// What it stresses: the `ReceivingInput` loading/typing path and MoveCall
// binding for `Receiving<T>` parameters.
// ---------------------------------------------------------------------------
fn receive_sui_coin_to_parent(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![
            refs.parent_key_box_input(),
            refs.receiving_coin_input(),
        ],
        commands: vec![fixture_call(
            "receive_sui_coin",
            vec![],
            vec![Argument::Input(0), Argument::Input(1)],
        )],
    }
}

// ---------------------------------------------------------------------------
// Scenario 43 — `Receiving<KeyBox>` resolved into the parent `KeyBox`
// ---------------------------------------------------------------------------
fn receive_key_box_to_parent(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![
            refs.parent_key_box_input(),
            refs.receiving_key_box_input(),
        ],
        commands: vec![fixture_call(
            "receive_key_box",
            vec![],
            vec![Argument::Input(0), Argument::Input(1)],
        )],
    }
}

// ---------------------------------------------------------------------------
// Scenarios 44–57 — Typed error seeds (reach `Typing`, return `Err`)
//
// These deliberately exercise type/argument validation branches inside
// `typing::translate_and_verify` that the happy-path seeds never hit.
// ---------------------------------------------------------------------------

// `take_u64` expects one argument; supply two.
fn err_fixture_wrong_arity() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![
            sui_types::transaction::CallArg::Pure(bcs::to_bytes(&1u64).unwrap()),
            sui_types::transaction::CallArg::Pure(bcs::to_bytes(&2u64).unwrap()),
        ],
        commands: vec![fixture_call(
            "take_u64",
            vec![],
            vec![Argument::Input(0), Argument::Input(1)],
        )],
    }
}

// `take_u64` expects `u64`; supply BCS for `u8`.
fn err_fixture_wrong_primitive() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(bcs::to_bytes(&1u8).unwrap())],
        commands: vec![fixture_call("take_u64", vec![], vec![Argument::Input(0)])],
    }
}

// `Input(99)` is out of bounds for a PTB with a single pure input.
fn err_input_index_oob() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(bcs::to_bytes(&1u64).unwrap())],
        commands: vec![fixture_call("take_u64", vec![], vec![Argument::Input(99)])],
    }
}

// `coin::value<T>` expects `T = SUI`; supply `Coin<SUI>` as the type argument.
fn err_coin_value_wrong_type_arg(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![refs.owned_coin_input()],
        commands: vec![move_call(
            sui_pkg(),
            "coin",
            "value",
            vec![sui_coin_type()],
            vec![Argument::Input(0)],
        )],
    }
}

// `SplitCoins` with one amount produces `NestedResult(0, 0)` only.
fn err_nested_result_secondary_oob() -> ProgrammableTransaction {
    let amt = bcs::to_bytes(&1u64).unwrap();
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    ProgrammableTransaction {
        inputs: vec![
            sui_types::transaction::CallArg::Pure(amt),
            sui_types::transaction::CallArg::Pure(addr),
        ],
        commands: vec![
            Command::SplitCoins(Argument::GasCoin, vec![Argument::Input(0)]),
            Command::TransferObjects(vec![Argument::NestedResult(0, 3)], Argument::Input(1)),
        ],
    }
}

// `MergeCoins` returns no results; `Result(0)` is invalid arity.
fn err_merge_invalid_result_arity(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    ProgrammableTransaction {
        inputs: vec![
            refs.owned_coin_input(),
            refs.second_owned_coin_input(),
            sui_types::transaction::CallArg::Pure(addr),
        ],
        commands: vec![
            Command::MergeCoins(Argument::Input(0), vec![Argument::Input(1)]),
            Command::TransferObjects(vec![Argument::Result(0)], Argument::Input(2)),
        ],
    }
}

// Immutable objects cannot be transferred by value.
fn err_transfer_immutable_by_value(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    ProgrammableTransaction {
        inputs: vec![
            refs.immutable_coin_input(),
            sui_types::transaction::CallArg::Pure(addr),
        ],
        commands: vec![Command::TransferObjects(
            vec![Argument::Input(0)],
            Argument::Input(1),
        )],
    }
}

// `use_mut_ref` expects `&mut u64`; pass an owned coin object input.
fn err_mut_ref_on_coin_object(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![refs.owned_coin_input()],
        commands: vec![fixture_call("use_mut_ref", vec![], vec![Argument::Input(0)])],
    }
}

// `option::some<u64>` with BCS bytes for a `u8` value.
fn err_option_inner_type_mismatch() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(bcs::to_bytes(&1u8).unwrap())],
        commands: vec![move_call(
            stdlib_pkg(),
            "option",
            "some",
            vec![TypeInput::U64],
            vec![Argument::Input(0)],
        )],
    }
}

// `MakeMoveVec(Some(u64), …)` with a `u8` pure input.
fn err_make_move_vec_elem_type_mismatch() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(bcs::to_bytes(&1u8).unwrap())],
        commands: vec![Command::MakeMoveVec(
            Some(TypeInput::U64),
            vec![Argument::Input(0)],
        )],
    }
}

// Consume the same `KeyBox` object input in two by-value MoveCalls.
fn err_object_input_reuse_after_move(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![refs.parent_key_box_input()],
        commands: vec![
            fixture_call("take_key_box", vec![], vec![Argument::Input(0)]),
            fixture_call("take_key_box", vec![], vec![Argument::Input(0)]),
        ],
    }
}

// `Result(99)` is out of bounds on an empty command list.
fn err_result_index_oob() -> ProgrammableTransaction {
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(addr)],
        commands: vec![Command::TransferObjects(
            vec![Argument::Result(99)],
            Argument::Input(0),
        )],
    }
}

// `TransferObjects` recipient must be an `address`; pass a `u64` pure input.
fn err_transfer_wrong_recipient_type() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(bcs::to_bytes(&1u64).unwrap())],
        commands: vec![Command::TransferObjects(
            vec![Argument::GasCoin],
            Argument::Input(0),
        )],
    }
}

// `SplitCoins` requires a mutable reference; immutable coin inputs cannot satisfy it.
fn err_split_immutable_coin(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    let amt = bcs::to_bytes(&1u64).unwrap();
    ProgrammableTransaction {
        inputs: vec![
            refs.immutable_coin_input(),
            sui_types::transaction::CallArg::Pure(amt),
        ],
        commands: vec![Command::SplitCoins(
            Argument::Input(0),
            vec![Argument::Input(1)],
        )],
    }
}

// `unbox` expects a `Box`; thread a `u64` result from `take_u64` instead.
fn err_fixture_struct_type_mismatch() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(bcs::to_bytes(&1u64).unwrap())],
        commands: vec![
            fixture_call("take_u64", vec![], vec![Argument::Input(0)]),
            fixture_call("unbox", vec![], vec![Argument::Result(0)]),
        ],
    }
}

// `from_u256` expects 32 bytes; supply a truncated `u64` BCS payload.
fn err_from_u256_truncated_bytes() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(bcs::to_bytes(&1u64).unwrap())],
        commands: vec![move_call(
            sui_pkg(),
            "address",
            "from_u256",
            vec![],
            vec![Argument::Input(0)],
        )],
    }
}

// ---------------------------------------------------------------------------
// Scenarios 60–71 — verify-pass coverage (move_functions, drop_safety,
// private_entry_arguments, framework MoveCalls)
// ---------------------------------------------------------------------------

// Scenario 60 — private non-`entry` function → `NonEntryFunctionInvoked`.
fn err_private_non_entry() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(
            bcs::to_bytes(&1u64).unwrap(),
        )],
        commands: vec![fixture_call(
            "private_non_entry",
            vec![],
            vec![Argument::Input(0)],
        )],
    }
}

// Scenario 61 — private `entry` with a plain primitive argument (OK path).
fn fixture_private_entry_ok() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(
            bcs::to_bytes(&42u64).unwrap(),
        )],
        commands: vec![fixture_call(
            "private_take_u64",
            vec![],
            vec![Argument::Input(0)],
        )],
    }
}

// Scenario 62 — hot-potato argument to a private `entry` while the clique stays hot.
// The second call consumes the sibling hot potato so `drop_safety` passes; the error is
// reported by `private_entry_arguments` on the first call.
fn err_hot_potato_private_entry() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![],
        commands: vec![
            fixture_call("two_hot_potatoes", vec![], vec![]),
            fixture_call(
                "take_hot_potato",
                vec![],
                vec![Argument::NestedResult(0, 0)],
            ),
            fixture_call(
                "take_hot_potato",
                vec![],
                vec![Argument::NestedResult(0, 1)],
            ),
        ],
    }
}

// Scenario 63 — unused hot-potato result at end of PTB → `UnusedValueWithoutDrop`.
fn err_unused_hot_potato() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![],
        commands: vec![fixture_call("make_hot_potato", vec![], vec![])],
    }
}

// Scenario 64 — multi-return hot potato: consume one, leave the other unused.
fn err_unused_multi_return_hot_potato() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![],
        commands: vec![
            fixture_call("two_hot_potatoes", vec![], vec![]),
            fixture_call(
                "take_hot_potato",
                vec![],
                vec![Argument::NestedResult(0, 1)],
            ),
        ],
    }
}

// Scenario 65 — `&mut u64` borrow of a pure input (OK; distinct from seed 52 on coin).
fn fixture_mut_ref_pure_u64() -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![sui_types::transaction::CallArg::Pure(
            bcs::to_bytes(&9u64).unwrap(),
        )],
        commands: vec![fixture_call("use_mut_ref", vec![], vec![Argument::Input(0)])],
    }
}

// Scenario 66 — `coin::split` via MoveCall; consume split coin and transfer remainder.
fn move_call_coin_split_consume(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    let amt = bcs::to_bytes(&1000u64).unwrap();
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    ProgrammableTransaction {
        inputs: vec![
            refs.owned_coin_input(),
            sui_types::transaction::CallArg::Pure(amt),
            sui_types::transaction::CallArg::Pure(addr),
        ],
        commands: vec![
            move_call(
                sui_pkg(),
                "coin",
                "split",
                vec![sui_type()],
                vec![Argument::Input(0), Argument::Input(1)],
            ),
            move_call(
                sui_pkg(),
                "coin",
                "destroy_zero",
                vec![sui_type()],
                vec![Argument::Result(0)],
            ),
            Command::TransferObjects(vec![Argument::Input(0)], Argument::Input(2)),
        ],
    }
}

// Scenario 67 — `coin::split` leaves an owned coin result unused.
fn err_unused_coin_split_result(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    let amt = bcs::to_bytes(&1000u64).unwrap();
    ProgrammableTransaction {
        inputs: vec![
            refs.owned_coin_input(),
            sui_types::transaction::CallArg::Pure(amt),
        ],
        commands: vec![move_call(
            sui_pkg(),
            "coin",
            "split",
            vec![sui_type()],
            vec![Argument::Input(0), Argument::Input(1)],
        )],
    }
}

// Scenario 68 — `coin::join` via MoveCall on two owned coin inputs.
fn move_call_coin_join(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    ProgrammableTransaction {
        inputs: vec![
            refs.owned_coin_input(),
            refs.second_owned_coin_input(),
            sui_types::transaction::CallArg::Pure(addr),
        ],
        commands: vec![
            move_call(
                sui_pkg(),
                "coin",
                "join",
                vec![sui_type()],
                vec![Argument::Input(0), Argument::Input(1)],
            ),
            Command::TransferObjects(vec![Argument::Input(0)], Argument::Input(2)),
        ],
    }
}

// Scenario 69 — `transfer::public_freeze_object<KeyBox>`.
fn move_call_public_freeze_key_box(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![refs.parent_key_box_input()],
        commands: vec![move_call(
            sui_pkg(),
            "transfer",
            "public_freeze_object",
            vec![key_box_type()],
            vec![Argument::Input(0)],
        )],
    }
}

// Scenario 70 — `transfer::public_share_object<KeyBox>`.
fn move_call_public_share_key_box(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    ProgrammableTransaction {
        inputs: vec![refs.parent_key_box_input()],
        commands: vec![move_call(
            sui_pkg(),
            "transfer",
            "public_share_object",
            vec![key_box_type()],
            vec![Argument::Input(0)],
        )],
    }
}

// Scenario 71 — `transfer::transfer<KeyBox>` hits private-generics rejection.
fn err_transfer_private_generics(refs: FuzzHarnessObjectRefs) -> ProgrammableTransaction {
    let addr = bcs::to_bytes(&SuiAddress::ZERO).unwrap();
    ProgrammableTransaction {
        inputs: vec![
            refs.parent_key_box_input(),
            sui_types::transaction::CallArg::Pure(addr),
        ],
        commands: vec![move_call(
            sui_pkg(),
            "transfer",
            "transfer",
            vec![key_box_type()],
            vec![Argument::Input(0), Argument::Input(1)],
        )],
    }
}

// ---------------------------------------------------------------------------

fn current_heap_bytes() -> u64 {
    // Advancing the epoch flushes per-thread cache into the global stats.
    epoch::mib()
        .expect("jemalloc epoch mib")
        .advance()
        .expect("jemalloc epoch advance");
    stats::allocated::mib()
        .expect("jemalloc allocated mib")
        .read()
        .expect("jemalloc allocated read") as u64
}

enum ValidationOutcome {
    BcsFailed(String),
    Typed {
        stage: PipelineStage,
        result: Result<(), ExecutionFailure>,
    },
}

fn format_validation(outcome: &ValidationOutcome) -> (String, String) {
    match outcome {
        ValidationOutcome::BcsFailed(err) => ("—".into(), format!("BCS decode failed: {err}")),
        ValidationOutcome::Typed { stage, result: Ok(()) } => {
            (format!("{stage:?}"), "OK".into())
        }
        ValidationOutcome::Typed { stage, result: Err(err) } => {
            let mut msg = err.to_string();
            if let Some(cmd) = err.command() {
                msg.push_str(&format!(" (command {cmd})"));
            }
            (format!("{stage:?}"), msg)
        }
    }
}

fn print_validation_report(entries: &[(String, ValidationOutcome, u64)]) {
    println!("Pipeline validation (`run_typing` per corpus file):\n");
    println!("{:<42} {:>8}  outcome", "file", "stage");
    println!("{}", "-".repeat(90));
    for (name, outcome, _) in entries {
        let (stage, msg) = format_validation(outcome);
        println!("{name:<42} {stage:>8}  {msg}");
    }
    println!();
}

fn main() {
    let dir = Path::new("corpus");
    fs::create_dir_all(dir).expect("failed to create corpus/");

    // Regenerate from scratch so stale `.bin` files from prior runs are not validated.
    for entry in fs::read_dir(dir).expect("failed to read corpus/") {
        let entry = entry.expect("failed to read corpus entry");
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "bin") {
            fs::remove_file(&path)
                .unwrap_or_else(|e| panic!("remove {}: {e}", path.display()));
        }
    }

    let (_harness_objects, harness_refs) = build_fuzz_harness_objects();

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
    write(dir, "17_move_call_no_args", move_call_no_args());
    write(dir, "18_move_call_pure_primitive", move_call_pure_primitive());
    write(dir, "19_move_call_vector_arg", move_call_vector_arg());
    write(dir, "20_move_call_generic_type_arg", move_call_generic_type_arg());
    write(dir, "21_move_call_reference_arg", move_call_reference_arg());
    write(dir, "22_move_call_result_chain_64", move_call_result_chain(64));
    write(dir, "23_move_call_make_vec_of_results_64", move_call_make_vec_of_results(64));
    write(dir, "24_make_move_vec_none_infer", make_move_vec_none_infer());
    write(dir, "25_make_move_vec_empty_typed", make_move_vec_empty_typed());
    write(dir, "26_fixture_no_args", fixture_no_args());
    write(dir, "27_fixture_take_primitive", fixture_take_primitive());
    write(dir, "28_fixture_struct_roundtrip", fixture_struct_roundtrip());
    write(dir, "29_fixture_generic_identity", fixture_generic_identity());
    write(dir, "30_fixture_multi_return", fixture_multi_return());
    write(dir, "31_fixture_make_pair", fixture_make_pair());
    write(dir, "32_fixture_reference_arg", fixture_reference_arg());
    write(dir, "33_split_owned_coin", split_owned_coin(harness_refs));
    write(dir, "34_merge_two_owned_coins", merge_two_owned_coins(harness_refs));
    write(dir, "35_transfer_owned_coin", transfer_owned_coin(harness_refs));
    write(dir, "36_split_shared_coin", split_shared_coin(harness_refs));
    write(
        dir,
        "37_move_call_immutable_coin_ref",
        move_call_immutable_coin_ref(harness_refs),
    );
    write(
        dir,
        "38_move_call_owned_coin_ref",
        move_call_owned_coin_ref(harness_refs),
    );
    write(dir, "39_transfer_key_box_object", transfer_key_box_object(harness_refs));
    write(
        dir,
        "40_move_call_key_box_by_value",
        move_call_key_box_by_value(harness_refs),
    );
    write(
        dir,
        "41_move_call_key_box_ref",
        move_call_key_box_ref(harness_refs),
    );
    write(
        dir,
        "42_receive_sui_coin_to_parent",
        receive_sui_coin_to_parent(harness_refs),
    );
    write(
        dir,
        "43_receive_key_box_to_parent",
        receive_key_box_to_parent(harness_refs),
    );
    write(dir, "44_err_fixture_wrong_arity", err_fixture_wrong_arity());
    write(dir, "45_err_fixture_wrong_primitive", err_fixture_wrong_primitive());
    write(dir, "46_err_input_index_oob", err_input_index_oob());
    write(
        dir,
        "47_err_coin_value_wrong_type_arg",
        err_coin_value_wrong_type_arg(harness_refs),
    );
    write(
        dir,
        "48_err_nested_result_secondary_oob",
        err_nested_result_secondary_oob(),
    );
    write(
        dir,
        "49_err_merge_invalid_result_arity",
        err_merge_invalid_result_arity(harness_refs),
    );
    write(
        dir,
        "50_err_transfer_immutable_by_value",
        err_transfer_immutable_by_value(harness_refs),
    );
    write(dir, "51_err_option_inner_type_mismatch", err_option_inner_type_mismatch());
    write(
        dir,
        "52_err_mut_ref_on_coin_object",
        err_mut_ref_on_coin_object(harness_refs),
    );
    write(
        dir,
        "53_err_make_move_vec_elem_type_mismatch",
        err_make_move_vec_elem_type_mismatch(),
    );
    write(
        dir,
        "54_err_object_input_reuse_after_move",
        err_object_input_reuse_after_move(harness_refs),
    );
    write(dir, "55_err_result_index_oob", err_result_index_oob());
    write(
        dir,
        "56_err_transfer_wrong_recipient_type",
        err_transfer_wrong_recipient_type(),
    );
    write(
        dir,
        "57_err_split_immutable_coin",
        err_split_immutable_coin(harness_refs),
    );
    write(
        dir,
        "58_err_fixture_struct_type_mismatch",
        err_fixture_struct_type_mismatch(),
    );
    write(
        dir,
        "59_err_from_u256_truncated_bytes",
        err_from_u256_truncated_bytes(),
    );
    write(dir, "60_err_private_non_entry", err_private_non_entry());
    write(dir, "61_fixture_private_entry_ok", fixture_private_entry_ok());
    write(
        dir,
        "62_err_hot_potato_private_entry",
        err_hot_potato_private_entry(),
    );
    write(dir, "63_err_unused_hot_potato", err_unused_hot_potato());
    write(
        dir,
        "64_err_unused_multi_return_hot_potato",
        err_unused_multi_return_hot_potato(),
    );
    write(dir, "65_fixture_mut_ref_pure_u64", fixture_mut_ref_pure_u64());
    write(
        dir,
        "66_move_call_coin_split_consume",
        move_call_coin_split_consume(harness_refs),
    );
    write(
        dir,
        "67_err_unused_coin_split_result",
        err_unused_coin_split_result(harness_refs),
    );
    write(
        dir,
        "68_move_call_coin_join",
        move_call_coin_join(harness_refs),
    );
    write(
        dir,
        "69_move_call_public_freeze_key_box",
        move_call_public_freeze_key_box(harness_refs),
    );
    write(
        dir,
        "70_move_call_public_share_key_box",
        move_call_public_share_key_box(harness_refs),
    );
    write(
        dir,
        "71_err_transfer_private_generics",
        err_transfer_private_generics(harness_refs),
    );

    println!("\nCorpus ready in ./corpus/\n");

    // Run each corpus file through the real typing pipeline: report stage + error,
    // then measure heap delta for HEAP_DELTA_LIMIT_BYTES calibration.
    println!("Validating corpus and calibrating heap threshold (building fixture — may take a moment)...\n");

    let fixture = Fixture::new();

    let mut entries: Vec<(String, ValidationOutcome, u64)> = fs::read_dir(dir)
        .expect("failed to read corpus/")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "bin"))
        .map(|e| {
            let path = e.path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let bytes = fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));

            let heap_before = current_heap_bytes();
            let outcome = match bcs::from_bytes::<ProgrammableTransaction>(&bytes) {
                Err(err) => ValidationOutcome::BcsFailed(err.to_string()),
                Ok(ptb) => {
                    let (stage, result) = run_typing(&fixture, ptb);
                    ValidationOutcome::Typed { stage, result }
                }
            };
            let delta = current_heap_bytes().saturating_sub(heap_before);
            (name, outcome, delta)
        })
        .collect();

    entries.sort_by_key(|(name, _, _)| name.clone());

    print_validation_report(&entries);

    println!("Heap delta per corpus file:\n");
    println!("{:<45} {:>12}", "file", "heap delta");
    println!("{}", "-".repeat(59));
    let mut max_delta: u64 = 0;
    for (name, _, delta) in &entries {
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
    // re-calibrate by plotting the actual heap-delta distribution across all
    // inputs that reached run_typing and tighten the threshold to e.g. the
    // 99.9th percentile plus one multiplier step.
    let suggested = (max_delta * 5).max(1024 * 1024);
    let suggested_mib = suggested.div_ceil(1024 * 1024);
    println!();
    println!("Max observed delta : {} KiB", max_delta / 1024);
    println!("Suggested HEAP_DELTA_LIMIT_BYTES: {suggested_mib} MiB  ({suggested} bytes)");
    println!();
    println!(
        "This is a seed-based estimate (5× worst seed).  Re-calibrate after a \
         ~10-minute warm-up run using the actual heap-delta distribution."
    );
}
