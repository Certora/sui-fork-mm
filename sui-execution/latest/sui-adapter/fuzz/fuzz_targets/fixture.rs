// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared fixture and harness logic used by both `translate_and_verify` (fuzzer)
//! and `gen_corpus` (corpus generator + calibration).

use sui_adapter_latest::{
    data_store::{
        cached_package_store::CachedPackageStore,
        transaction_package_store::TransactionPackageStore,
    },
    execution_mode::{ExecutionMode, Normal},
    execution_value::ExecutionState,
    gas_charger::{GasCharger, GasPayment, PaymentLocation},
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
    base_types::{ObjectID, SuiAddress, TxContext},
    digests::TransactionDigest,
    error::ExecutionErrorTrait,
    execution_status::ExecutionErrorKind,
    in_memory_storage::InMemoryStorage,
    transaction::{InputObjects, ProgrammableTransaction},
};

pub type Mode = Normal;

/// Owned, side-effect-free state held for the lifetime of the worker thread. Everything that
/// *borrows* from these (the VM instances, the package store, the env) is rebuilt per iteration.
pub struct Fixture {
    pub protocol_config: sui_protocol_config::ProtocolConfig,
    pub vm: move_vm_runtime::runtime::MoveRuntime,
    pub store: InMemoryStorage,
}

impl Fixture {
    pub fn new() -> Self {
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

/// Mirrors `static_programmable_transactions::execute` up to — but not including —
/// the interpreter. Returns `Err` on any rejection (expected); the body panicking is the bug we
/// want LibAFL to catch.
/// The last pipeline stage reached by a `run_typing` call.
/// Useful for diagnosing whether fuzz inputs are actually reaching the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineStage {
    /// Failed during linkage analysis (most fuzz inputs stop here because they
    /// reference packages absent from the framework-only fixture store).
    Linkage,
    /// Linkage passed; failed during the loading/translation pass.
    Loading,
    /// Reached `typing::translate_and_verify` (the actual target).
    /// The call may have returned Ok or Err — both count as reaching the target.
    Typing,
}

/// Mirrors `static_programmable_transactions::execute` up to — but not including —
/// the interpreter. Returns the last stage reached alongside the result so callers
/// can track pipeline depth without instrumenting the internals.
pub fn run_typing(
    fixture: &Fixture,
    txn: ProgrammableTransaction,
) -> (PipelineStage, Result<(), <Mode as ExecutionMode>::Error>) {
    let protocol_config = &fixture.protocol_config;
    let vm = &fixture.vm;

    let tx_digest = TransactionDigest::default();
    let mut gas_charger = GasCharger::new_unmetered(tx_digest);
 
    let gas_payment = Some(GasPayment {
        location: PaymentLocation::Coin(ObjectID::ZERO),
        amount: u64::MAX,
    });

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

    let mut state_view = TemporaryStore::new(
        &fixture.store,
        InputObjects::new(vec![]),
        /* receiving_objects */ vec![],
        tx_digest,
        protocol_config,
        /* cur_epoch */ 0,
    );
    let state_view: &mut dyn ExecutionState = &mut state_view;

    // Use a closure with `?` so each stage can early-return while the outer
    // function tracks which stage was last entered.
    let mut stage = PipelineStage::Linkage;
    let result = (|| {
        let package_store =
            CachedPackageStore::new(vm, TransactionPackageStore::new(&fixture.store));
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
                <Mode as ExecutionMode>::Error::new_with_source(
                    ExecutionErrorKind::InvalidLinkage,
                    e,
                )
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

        stage = PipelineStage::Loading;
        let lt = loading::translate::transaction::<Mode>(
            &mut meter,
            &env,
            &tx_context,
            /* withdrawal_compatibility_inputs */ None,
            gas_payment,
            txn,
        )?;

        stage = PipelineStage::Typing;
        let _typed = typing::translate_and_verify::<Mode>(&mut meter, &env, lt)?;

        Ok(())
    })();

    (stage, result)
}
