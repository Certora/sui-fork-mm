// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Synthetic Move package at address [`ADDRESS`] (`fuzz_fixture`).
//!
//! Compiled at harness startup and inserted into the framework-only store so
//! `MoveCall` fuzz inputs have a resolvable target with diverse signatures
//! (primitives, vectors, references, generics, structs, multiple returns).

use move_compiler::{
    Compiler as MoveCompiler,
    diagnostics::filter::unused_for_test_filter_scope,
    editions::{Edition, Flavor},
    shared::{NumericalAddress, PackageConfig},
};
use move_core_types::{account_address::AccountAddress, ident_str, language_storage::StructTag};
use serde::Serialize;
use std::{collections::BTreeMap, path::PathBuf};
use sui_types::{
    base_types::{MoveObjectType, ObjectID, ObjectRef, SequenceNumber, SuiAddress},
    digests::TransactionDigest,
    gas_coin::GAS,
    id::UID,
    move_package::MovePackage,
    object::{MoveObject, Object, Owner, OBJECT_START_VERSION},
    transaction::{Argument, CallArg, Command, ObjectArg, ProgrammableMoveCall, SharedObjectMutability},
    type_input::StructInput,
};
use sui_types::type_input::TypeInput;

/// Package address — distinct from system package IDs (`0x1`/`0x2`/…).
pub const ADDRESS: &str = "0xface";

pub const MODULE: &str = "fuzz_fixture";

const MODULE_SRC: &str = r#"
module 0xface::fuzz_fixture {
    use sui::coin::{Self, Coin};
    use sui::object::{Self, UID};
    use sui::sui::SUI;
    use sui::transfer::{Self, Receiving};

    public struct Box has copy, drop, store {
        v: u64,
    }

    public struct Pair<T> has copy, drop {
        a: T,
        b: T,
    }

    /// On-chain object with `key` — used by object-input and receiving seeds.
    public struct KeyBox has key, store {
        id: UID,
        v: u64,
    }

    /// `copy` without `drop` or `store` — a hot-potato type for private-entry checks.
    public struct HotPotato has copy {
        v: u64,
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

    public fun take_key_box(b: KeyBox): u64 {
        let KeyBox { id, v } = b;
        object::delete(id);
        v
    }

    public fun key_box_value(b: &KeyBox): u64 { b.v }

    public fun receive_sui_coin(parent: &mut KeyBox, ticket: Receiving<Coin<SUI>>): u64 {
        let c = transfer::public_receive(&mut parent.id, ticket);
        let v = coin::value(&c);
        transfer::public_transfer(c, @0x0);
        v
    }

    public fun receive_key_box(parent: &mut KeyBox, ticket: Receiving<KeyBox>): u64 {
        let child = transfer::public_receive(&mut parent.id, ticket);
        let KeyBox { id, v } = child;
        object::delete(id);
        v
    }

    /// Private non-`entry` function — invoking from a PTB should fail visibility checks.
    fun private_non_entry(x: u64): u64 { x }

    /// Private `entry` — valid to call from a PTB without hot-potato arguments.
    entry fun private_take_u64(x: u64) {
        let _ = x;
    }

    public fun make_hot_potato(): HotPotato {
        HotPotato { v: 0 }
    }

    public fun two_hot_potatoes(): (HotPotato, HotPotato) {
        (HotPotato { v: 0 }, HotPotato { v: 1 })
    }

    /// Private `entry` that takes a hot-potato argument by value.
    entry fun take_hot_potato(h: HotPotato) {
        let HotPotato { v: _ } = h;
    }
}
"#;

pub fn package_id() -> ObjectID {
    ObjectID::from_hex_literal(ADDRESS).expect("valid fuzz fixture address")
}

/// `ADDRESS::fuzz_fixture::KeyBox` as a PTB type argument.
pub fn key_box_type() -> TypeInput {
    TypeInput::Struct(Box::new(StructInput {
        address: AccountAddress::from(package_id()),
        module: MODULE.to_owned(),
        name: "KeyBox".to_owned(),
        type_params: vec![],
    }))
}

/// Build a `MoveCall` against the fuzz-fixture package.
pub fn move_call(
    function: &str,
    type_arguments: Vec<TypeInput>,
    arguments: Vec<Argument>,
) -> Command {
    Command::MoveCall(Box::new(ProgrammableMoveCall {
        package: package_id(),
        module: MODULE.to_owned(),
        function: function.to_owned(),
        type_arguments,
        arguments,
    }))
}

/// Compile [`MODULE_SRC`] and wrap it as an initial package object.
pub fn package_object(
    protocol_config: &sui_protocol_config::ProtocolConfig,
    dependencies: &[MovePackage],
) -> Object {
    let dir = tempfile::tempdir().expect("create tempdir for fixture source");
    let file_path = dir.path().join("fuzz_fixture.move");
    std::fs::write(&file_path, MODULE_SRC).expect("write fixture source");

    let named_addresses: BTreeMap<&str, NumericalAddress> = [
        ("std", NumericalAddress::parse_str("0x1").unwrap()),
        ("sui", NumericalAddress::parse_str("0x2").unwrap()),
    ]
    .into_iter()
    .collect();

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sui_sources = manifest_dir
        .join("../../../../crates/sui-framework/packages/sui-framework/sources");
    let stdlib_sources =
        manifest_dir.join("../../../../crates/sui-framework/packages/move-stdlib/sources");

    let (_, units) = MoveCompiler::from_files(
        None,
        vec![file_path.to_str().unwrap().to_string()],
        vec![
            sui_sources.to_string_lossy().into_owned(),
            stdlib_sources.to_string_lossy().into_owned(),
        ],
        named_addresses,
    )
    .set_default_config(PackageConfig {
        is_dependency: false,
        warning_filter: unused_for_test_filter_scope(),
        flavor: Flavor::Sui,
        edition: Edition::E2024_BETA,
    })
    .build_and_report()
    .expect("fuzz fixture package failed to compile");

    let modules: Vec<_> = units.into_iter().map(|u| u.named_module.module).collect();
    Object::new_package(
        &modules,
        TransactionDigest::default(),
        protocol_config,
        dependencies,
    )
    .expect("fuzz fixture package failed to build")
}

/// BCS layout of `ADDRESS::fuzz_fixture::KeyBox`.
#[derive(Serialize)]
struct KeyBoxFields {
    id: UID,
    v: u64,
}

fn key_box_struct_tag() -> StructTag {
    StructTag {
        address: package_id().into(),
        module: ident_str!(MODULE).to_owned(),
        name: ident_str!("KeyBox").to_owned(),
        type_params: vec![],
    }
}

/// Build an on-chain `KeyBox` object instance (type from this package).
pub fn key_box_object(id: ObjectID, owner: Owner, value: u64) -> Object {
    let contents = bcs::to_bytes(&KeyBoxFields {
        id: UID::new(id),
        v: value,
    })
    .expect("serialize KeyBox");
    let move_obj = unsafe {
        MoveObject::new_from_execution_with_limit(
            MoveObjectType::from(key_box_struct_tag()),
            true,
            OBJECT_START_VERSION,
            contents,
            256,
        )
        .expect("build KeyBox MoveObject")
    };
    Object::new_move(move_obj, owner, TransactionDigest::genesis_marker())
}

/// Sender used when building harness objects. Owned inputs are created with this
/// address so memory-safety checks align with [`run_typing`]'s `TxContext`.
pub const HARNESS_SENDER: SuiAddress = SuiAddress::ZERO;

/// Deterministic object IDs for harness store objects (distinct from [`ADDRESS`]).
const OWNED_COIN_1_ID: &str = "0xfeed";
const OWNED_COIN_2_ID: &str = "0xfeed1";
const SHARED_COIN_ID: &str = "0xfeed2";
const IMMUTABLE_COIN_ID: &str = "0xfeed3";
const PARENT_KEY_BOX_ID: &str = "0xfeed4";
const RECEIVING_COIN_ID: &str = "0xfeed5";
const RECEIVING_KEY_BOX_ID: &str = "0xfeed6";

/// Object references for the synthetic coins/objects inserted into the fixture
/// store. `gen_corpus` uses these when building PTB seeds with `CallArg::Object`.
#[derive(Debug, Clone, Copy)]
pub struct FuzzHarnessObjectRefs {
    pub owned_coin: ObjectRef,
    pub second_owned_coin: ObjectRef,
    pub shared_coin_id: ObjectID,
    pub shared_coin_initial_version: SequenceNumber,
    pub immutable_coin: ObjectRef,
    pub parent_key_box: ObjectRef,
    pub receiving_coin: ObjectRef,
    pub receiving_key_box: ObjectRef,
}

impl FuzzHarnessObjectRefs {
    pub fn owned_coin_input(self) -> CallArg {
        CallArg::Object(ObjectArg::ImmOrOwnedObject(self.owned_coin))
    }

    pub fn second_owned_coin_input(self) -> CallArg {
        CallArg::Object(ObjectArg::ImmOrOwnedObject(self.second_owned_coin))
    }

    pub fn shared_coin_mut_input(self) -> CallArg {
        CallArg::Object(ObjectArg::SharedObject {
            id: self.shared_coin_id,
            initial_shared_version: self.shared_coin_initial_version,
            mutability: SharedObjectMutability::Mutable,
        })
    }

    pub fn immutable_coin_input(self) -> CallArg {
        CallArg::Object(ObjectArg::ImmOrOwnedObject(self.immutable_coin))
    }

    pub fn parent_key_box_input(self) -> CallArg {
        CallArg::Object(ObjectArg::ImmOrOwnedObject(self.parent_key_box))
    }

    pub fn receiving_coin_input(self) -> CallArg {
        CallArg::Object(ObjectArg::Receiving(self.receiving_coin))
    }

    pub fn receiving_key_box_input(self) -> CallArg {
        CallArg::Object(ObjectArg::Receiving(self.receiving_key_box))
    }
}

/// Build the owned/shared/immutable coins and KeyBox objects that back
/// object-input PTB seeds.
pub fn build_fuzz_harness_objects() -> (Vec<Object>, FuzzHarnessObjectRefs) {
    let sender = HARNESS_SENDER;

    let owned_id = ObjectID::from_hex_literal(OWNED_COIN_1_ID).expect("valid owned coin id");
    let owned = sui_coin_object(owned_id, Owner::AddressOwner(sender), 10_000_000);
    let owned_coin = owned.compute_object_reference();

    let second_id = ObjectID::from_hex_literal(OWNED_COIN_2_ID).expect("valid second owned coin id");
    let second_owned = sui_coin_object(second_id, Owner::AddressOwner(sender), 5_000_000);
    let second_owned_coin = second_owned.compute_object_reference();

    let shared_id = ObjectID::from_hex_literal(SHARED_COIN_ID).expect("valid shared coin id");
    let shared_move =
        MoveObject::new_coin(GAS::type_tag(), OBJECT_START_VERSION, shared_id, 8_000_000);
    let shared_coin_initial_version = shared_move.version();
    let shared = Object::new_move(
        shared_move,
        Owner::Shared {
            initial_shared_version: shared_coin_initial_version,
        },
        TransactionDigest::genesis_marker(),
    );

    let immutable_id =
        ObjectID::from_hex_literal(IMMUTABLE_COIN_ID).expect("valid immutable coin id");
    let immutable = sui_coin_object(immutable_id, Owner::Immutable, 3_000_000);
    let immutable_coin = immutable.compute_object_reference();

    let parent_id =
        ObjectID::from_hex_literal(PARENT_KEY_BOX_ID).expect("valid parent key box id");
    let parent_key_box = key_box_object(parent_id, Owner::AddressOwner(sender), 42);
    let parent_key_box_ref = parent_key_box.compute_object_reference();

    let receiving_coin_id =
        ObjectID::from_hex_literal(RECEIVING_COIN_ID).expect("valid receiving coin id");
    let receiving_coin = sui_coin_object(
        receiving_coin_id,
        Owner::AddressOwner(SuiAddress::from(parent_id)),
        1_000,
    );
    let receiving_coin_ref = receiving_coin.compute_object_reference();

    let receiving_key_box_id =
        ObjectID::from_hex_literal(RECEIVING_KEY_BOX_ID).expect("valid receiving key box id");
    let receiving_key_box = key_box_object(
        receiving_key_box_id,
        Owner::AddressOwner(SuiAddress::from(parent_id)),
        7,
    );
    let receiving_key_box_ref = receiving_key_box.compute_object_reference();

    let refs = FuzzHarnessObjectRefs {
        owned_coin,
        second_owned_coin,
        shared_coin_id: shared_id,
        shared_coin_initial_version,
        immutable_coin,
        parent_key_box: parent_key_box_ref,
        receiving_coin: receiving_coin_ref,
        receiving_key_box: receiving_key_box_ref,
    };
    let objects = vec![
        owned,
        second_owned,
        shared,
        immutable,
        parent_key_box,
        receiving_coin,
        receiving_key_box,
    ];
    (objects, refs)
}

/// `0x2::coin::Coin<0x2::sui::SUI>` — matches framework MoveCall signatures like
/// `coin::value<T>`, unlike the distinct `GasCoin` runtime type used for gas payment.
fn sui_coin_object(id: ObjectID, owner: Owner, value: u64) -> Object {
    let move_obj = MoveObject::new_coin(GAS::type_tag(), OBJECT_START_VERSION, id, value);
    Object::new_move(move_obj, owner, TransactionDigest::genesis_marker())
}
