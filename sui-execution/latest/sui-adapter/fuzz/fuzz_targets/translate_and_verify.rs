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

use std::{num::NonZeroUsize, path::PathBuf};

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{ExitKind, InProcessExecutor},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::HitcountsMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{AsSlice, rands::StdRand, tuples::tuple_list};
use libafl_targets::std_edges_map_observer;

use sui_adapter_latest::{
    data_store::{
        cached_package_store::CachedPackageStore,
        transaction_package_store::TransactionPackageStore,
    },
    execution_mode::{ExecutionMode, Normal},
    execution_value::ExecutionState,
    gas_charger::GasCharger,
    static_programmable_transactions::{
        env::Env,
        linkage::analysis::LinkageAnalyzer,
        loading,
        metering::translation_meter::TranslationMeter,
        typing,
    },
    temporary_store::TemporaryStore,
};
use sui_types::{
    base_types::{SuiAddress, TxContext},
    digests::TransactionDigest,
    error::ExecutionErrorTrait,
    execution_status::ExecutionErrorKind,
    in_memory_storage::InMemoryStorage,
    transaction::{InputObjects, ProgrammableTransaction},
};

/// SanitizerCoverage emits an indirect-call callback that `libafl_targets` only defines via its C
/// cmplog shim (not enabled here). We don't use indirect-call coverage — edge coverage from
/// trace-pc-guard is the signal — so provide a no-op so the binary links.
#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_pc_indir(_callee: usize) {}

/// The concrete execution mode to exercise. `Normal` is the production on-chain path.
type Mode = Normal;

/// Owned, side-effect-free state held for the lifetime of the worker thread. Everything that
/// *borrows* from these (the VM instances, the package store, the env) is rebuilt per iteration.
struct Fixture {
    protocol_config: sui_protocol_config::ProtocolConfig,
    vm: move_vm_runtime::runtime::MoveRuntime,
    store: InMemoryStorage,
}

impl Fixture {
    fn new() -> Self {
        let protocol_config = sui_protocol_config::ProtocolConfig::get_for_max_version_UNSAFE();
        let natives = sui_move_natives_latest::all_natives(/* silent */ true, &protocol_config);
        let vm = sui_adapter_latest::adapter::new_move_runtime(natives, &protocol_config)
            .expect("failed to build MoveRuntime");
        // Seed the store with the system packages only — this is the entire "framework".
        let store =
            InMemoryStorage::new(sui_framework::BuiltInFramework::genesis_objects().collect());
        Self {
            protocol_config,
            vm,
            store,
        }
    }
}

thread_local! {
    static FIXTURE: Fixture = Fixture::new();
}

/// Mirrors `static_programmable_transactions::execute` (mod.rs:51-92) up to — but not including —
/// the interpreter. Returns `Err` on any rejection (expected); the body panicking is the bug we
/// want LibAFL to catch.
fn run_typing(
    fixture: &Fixture,
    txn: ProgrammableTransaction,
) -> Result<(), <Mode as ExecutionMode>::Error> {
    let protocol_config = &fixture.protocol_config;
    let vm = &fixture.vm;

    let tx_digest = TransactionDigest::default();
    let mut gas_charger = GasCharger::new_unmetered(tx_digest);
    let gas_payment = gas_charger.gas_payment_amount();

    let tx_context = TxContext::new_from_components(
        &SuiAddress::ZERO,
        &tx_digest,
        /* epoch_id */ &0u64,
        /* epoch_timestamp_ms */ 0,
        /* rgp */ 1,
        /* gas_price */ 1,
        /* gas_budget */ u64::MAX,
        /* sponsor */ None,
        protocol_config,
    );

    // A no-op-write ExecutionState; the typing pass only reads from it. The interpreter (which
    // performs the writes) is never reached.
    let mut state_view = TemporaryStore::new(
        &fixture.store,
        InputObjects::new(vec![]),
        /* receiving_objects */ vec![],
        tx_digest,
        protocol_config,
        /* cur_epoch */ 0,
    );
    let state_view: &mut dyn ExecutionState = &mut state_view;

    // ---- env construction (mod.rs:52-75) ----
    let package_store = CachedPackageStore::new(vm, TransactionPackageStore::new(&fixture.store));
    let linkage_analysis = LinkageAnalyzer::new::<Mode>(protocol_config)?;
    let ptb_type_linkage = linkage_analysis
        .compute_input_type_resolution_linkage::<<Mode as ExecutionMode>::Error>(
            &txn,
            &package_store,
            state_view,
        )
        .and_then(|linkage| linkage.linkage_context::<<Mode as ExecutionMode>::Error>())?;
    let resolution_vm = vm
        .make_vm(&package_store.package_store, ptb_type_linkage)
        .map_err(|e| {
            <Mode as ExecutionMode>::Error::new_with_source(ExecutionErrorKind::InvalidLinkage, e)
        })?;

    let env: Env<Mode> = Env::new(
        protocol_config,
        vm,
        state_view,
        &package_store,
        &linkage_analysis,
        &resolution_vm,
    );
    let mut meter = TranslationMeter::new(protocol_config, &mut gas_charger);

    // ---- loading pass: produces the L::Transaction (mod.rs:81-89) ----
    let lt = loading::translate::transaction::<Mode>(
        &mut meter,
        &env,
        &tx_context,
        /* withdrawal_compatibility_inputs */ None,
        gas_payment,
        txn,
    )?;

    // ---- THE TARGET (mod.rs:91) ----
    let _typed = typing::translate_and_verify::<Mode>(&mut meter, &env, lt)?;

    // Stop here. No execution::interpreter::execute.
    Ok(())
}

fn main() -> Result<(), libafl::Error> {
    // The closure run on each input. Malformed bytes are skipped — seed the corpus with
    // BCS-serialized real PTBs for fast warm-up.
    let mut harness = |input: &BytesInput| {
        let bytes = input.target_bytes();
        if let Ok(txn) = bcs::from_bytes::<ProgrammableTransaction>(bytes.as_slice()) {
            FIXTURE.with(|fixture| {
                let _ = run_typing(fixture, txn);
            });
        }
        ExitKind::Ok
    };

    // Coverage map fed by the sancov trace-pc-guard hooks (see .cargo/config.toml).
    let edges_observer = HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") });

    // Novelty feedback (new coverage => keep the input); crashes/panics are the objective.
    let mut feedback = MaxMapFeedback::new(&edges_observer);
    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        StdRand::with_seed(0xC0FFEE),
        InMemoryCorpus::new(),
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        &mut feedback,
        &mut objective,
    )?;

    let monitor = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(monitor);

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(edges_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )?;

    // No corpus on disk yet: generate random seeds so the fuzzer has something to mutate.
    let mut generator = RandBytesGenerator::new(NonZeroUsize::new(64).unwrap());
    state.generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 16)?;

    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    Ok(())
}
