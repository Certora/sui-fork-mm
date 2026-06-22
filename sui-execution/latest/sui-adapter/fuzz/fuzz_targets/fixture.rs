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
};
use move_compiler::{Compiler as MoveCompiler, shared::NumericalAddress};
use std::collections::{BTreeMap, BTreeSet};
use sui_types::{
    TypeTag,
    base_types::{ObjectID, ObjectRef, SequenceNumber, SuiAddress, TxContext},
    committee::EpochId,
    digests::TransactionDigest,
    error::{ExecutionError, ExecutionErrorTrait, SuiResult},
    execution::{DynamicallyLoadedObjectMetadata, ExecutionResults},
    execution_status::ExecutionErrorKind,
    in_memory_storage::InMemoryStorage,
    object::Object,
    storage::{
        BackingPackageStore, ChildObjectResolver, DenyListResult, PackageObject, ParentSync,
        Storage,
    },
    transaction::ProgrammableTransaction,
};

pub type Mode = Normal;

/// Source for the fuzz-fixture package. Its module is declared at address
/// `0xface` — distinct from every system package ID (`0x1`/`0x2`/`0x3`/`0xb`/
/// `0xdee9`) so it can be added to the framework-only store without collision.
/// `gen_corpus` references this same ID when building MoveCall seeds. It is
/// deliberately self-contained (no
/// `use` of any other package) so it has no transitive dependencies and can be
/// inserted into the framework-only store as an initial package keyed solely on
/// its own address. Its only purpose is to give `MoveCall` fuzz inputs a real,
/// resolvable target with a wide variety of function signatures (primitives,
/// vectors, references, generics with ability bounds, structs, and
/// multiple-return functions) so the typing pass actually exercises MoveCall
/// resolution instead of bailing out at linkage/loading.
const FUZZ_FIXTURE_MODULE_SRC: &str = r#"
module 0xface::fuzz_fixture {
    public struct Box has copy, drop, store {
        v: u64,
    }

    public struct Pair<T> has copy, drop {
        a: T,
        b: T,
    }

    public fun nothing() {}

    public fun take_u8(x: u8): u8 { x }
    public fun take_u64(x: u64): u64 { x }
    public fun take_u128(x: u128): u128 { x }
    public fun take_u256(x: u256): u256 { x }
    public fun take_bool(b: bool): bool { b }
    public fun take_address(a: address): address { a }

    public fun take_vec_u64(_v: vector<u64>): u64 { 0 }
    public fun take_vec_address(_v: vector<address>): u64 { 0 }

    public fun use_imm_ref(_x: &u64): u64 { 0 }
    public fun use_mut_ref(_x: &mut u64) {}

    public fun identity<T>(x: T): T { x }
    public fun ignore<T: drop>(_x: T) {}

    public fun new_box(v: u64): Box { Box { v } }
    public fun unbox(b: Box): u64 { b.v }
    public fun box_value(b: &Box): u64 { b.v }

    public fun make_pair<T: copy + drop>(a: T, b: T): Pair<T> { Pair { a, b } }

    public fun two_values(): (u64, bool) { (0, false) }
    public fun swap<T>(a: T, b: T): (T, T) { (b, a) }
}
"#;

/// Compile [`FUZZ_FIXTURE_MODULE_SRC`] and wrap it as an initial package object.
/// The package ID is taken from the module's self-address (`0xface`), so it is
/// directly resolvable by PTBs that reference [`fuzz_fixture_package_id`].
fn fuzz_fixture_package_object(
    protocol_config: &sui_protocol_config::ProtocolConfig,
) -> Object {
    // Compile the self-contained source to a `CompiledModule` (mirrors the
    // test-only `compile_units` dev util, which we can't depend on here). `std`
    // is mapped to `0x1` for parity even though the module imports nothing.
    let dir = tempfile::tempdir().expect("create tempdir for fixture source");
    let file_path = dir.path().join("fuzz_fixture.move");
    std::fs::write(&file_path, FUZZ_FIXTURE_MODULE_SRC).expect("write fixture source");

    let named_addresses: std::collections::BTreeMap<&str, NumericalAddress> =
        [("std", NumericalAddress::parse_str("0x1").unwrap())]
            .into_iter()
            .collect();
    let (_, units) = MoveCompiler::from_files(
        None,
        vec![file_path.to_str().unwrap().to_string()],
        vec![],
        named_addresses,
    )
    .build_and_report()
    .expect("fuzz fixture package failed to compile");

    let modules: Vec<_> = units.into_iter().map(|u| u.named_module.module).collect();
    Object::new_package(
        &modules,
        TransactionDigest::default(),
        protocol_config,
        /* transitive_dependencies */ [],
    )
    .expect("fuzz fixture package failed to build")
}

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
        // Seed the store with the system packages plus a synthetic fuzz-fixture
        // package, so MoveCall fuzz inputs have a resolvable target with diverse
        // signatures (see `FUZZ_FIXTURE_MODULE_SRC`) rather than only the framework.
        let mut objects: Vec<Object> =
            sui_framework::BuiltInFramework::genesis_objects().collect();
        objects.push(fuzz_fixture_package_object(&protocol_config));
        let store = InMemoryStorage::new(objects);
        Self {
            protocol_config,
            vm,
            store,
        }
    }
}

/// Minimal `ExecutionState` for the typing pipeline.
///
/// The production `TemporaryStore` is compiled out under `--cfg=fuzzing` (it is only
/// needed by the interpreter/effects path), so the harness supplies its own. The
/// loading/typing pass only ever issues object/package *reads*, which we delegate to
/// the framework store; the mutating effects methods are unreachable here and are
/// implemented as benign no-ops so a stray call can never manufacture a false crash.
/// This type lives in the (uninstrumented) fuzz crate, so none of it counts toward
/// sancov edges.
struct HarnessState<'a> {
    inner: &'a InMemoryStorage,
}

impl BackingPackageStore for HarnessState<'_> {
    fn get_package_object(&self, package_id: &ObjectID) -> SuiResult<Option<PackageObject>> {
        self.inner.get_package_object(package_id)
    }
}

impl ChildObjectResolver for HarnessState<'_> {
    fn read_child_object(
        &self,
        parent: &ObjectID,
        child: &ObjectID,
        child_version_upper_bound: SequenceNumber,
    ) -> SuiResult<Option<Object>> {
        self.inner
            .read_child_object(parent, child, child_version_upper_bound)
    }

    fn get_object_received_at_version(
        &self,
        owner: &ObjectID,
        receiving_object_id: &ObjectID,
        receive_object_at_version: SequenceNumber,
        epoch_id: EpochId,
    ) -> SuiResult<Option<Object>> {
        self.inner.get_object_received_at_version(
            owner,
            receiving_object_id,
            receive_object_at_version,
            epoch_id,
        )
    }
}

impl ParentSync for HarnessState<'_> {
    fn get_latest_parent_entry_ref_deprecated(&self, object_id: ObjectID) -> Option<ObjectRef> {
        self.inner.get_latest_parent_entry_ref_deprecated(object_id)
    }
}

impl Storage for HarnessState<'_> {
    fn read_object(&self, id: &ObjectID) -> Option<&Object> {
        self.inner.get_object(id)
    }

    // Everything below is only reached by the interpreter/effects path, which the
    // typing fuzz target never runs. Benign no-ops keep fuzz fidelity intact.
    fn reset(&mut self) {}

    fn record_execution_results(
        &mut self,
        _results: ExecutionResults,
    ) -> Result<(), ExecutionError> {
        Ok(())
    }

    fn save_loaded_runtime_objects(
        &mut self,
        _loaded_runtime_objects: BTreeMap<ObjectID, DynamicallyLoadedObjectMetadata>,
    ) {
    }

    fn save_wrapped_object_containers(
        &mut self,
        _wrapped_object_containers: BTreeMap<ObjectID, ObjectID>,
    ) {
    }

    fn check_coin_deny_list(
        &self,
        _receiving_funds_type_and_owners: BTreeMap<TypeTag, BTreeSet<SuiAddress>>,
    ) -> DenyListResult {
        DenyListResult {
            result: Ok(()),
            num_non_gas_coin_owners: 0,
        }
    }

    fn record_generated_object_ids(&mut self, _generated_ids: BTreeSet<ObjectID>) {}
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

    let mut state_view = HarnessState {
        inner: &fixture.store,
    };
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
