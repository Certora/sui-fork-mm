// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Structure-aware mutator for `ProgrammableTransaction`.
//!
//! Operates on `BytesInput` whose bytes are a BCS-encoded `ProgrammableTransaction`.
//! If the bytes don't decode cleanly the mutator returns `Skipped` and lets havoc
//! handle the input as raw bytes.  When decoding succeeds, one mutation is chosen
//! uniformly at random from the table below, applied at the Rust-type level, and the
//! result is re-serialized.  BCS validity is preserved by construction.
//!
//! Mutation table
//! ──────────────
//! 0  AddSplitCoins        insert SplitCoins(GasCoin, [existing-pure-input])
//! 1  AddMergeCoins        insert MergeCoins(GasCoin, [Result(prev)])
//! 2  AddMakeMoveVec       insert MakeMoveVec(U64, [Input(0)])
//! 3  DupCommand           clone a random command and append it
//! 4  SwapCommands         swap two random commands
//! 5  RemoveCommand        drop a random command
//! 6  AddPureInput         append a fresh pure-u64 input
//! 7  RemoveInput          drop a random unused-looking input
//! 8  Scr ambleArgument     replace one Argument in a random command with GasCoin / Input(0) /
//!                         Result(n) / NestedResult(n,j)
//! 9  FanOutArgs           repeat the argument list of a random command N times (stress splatting)
//! 10 DeepResultChain      append a chain of MakeMoveVec wrapping the last result (stress Path clone)
//! 11 NestTypeArg          wrap the first type-arg of a random MoveCall one level deeper in vector<>
//! 12 AddMoveCall          insert a MoveCall to a known-valid function in the fuzz-fixture
//!                         package or 0x2::coin / 0x2::object / 0x2::transfer

use crate::fixture::{ADDRESS, MODULE};
use std::num::NonZeroUsize;

use libafl::{
    Error,
    corpus::CorpusId,
    inputs::{BytesInput, HasTargetBytes},
    mutators::{MutationResult, Mutator},
};
use libafl_bolts::{Named, rands::Rand};
use sui_types::{
    base_types::ObjectID,
    transaction::{Argument, CallArg, Command, ProgrammableMoveCall, ProgrammableTransaction},
    type_input::TypeInput,
};

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

fn pure_u64(v: u64) -> CallArg {
    CallArg::Pure(bcs::to_bytes(&v).unwrap())
}

/// Pick a random index in `0..len`; returns `None` when `len == 0`.
fn rand_idx<R: Rand>(rng: &mut R, len: usize) -> Option<usize> {
    NonZeroUsize::new(len).map(|n| rng.below(n))
}

// ──────────────────────────────────────────────────────────────────────────────
// Mutation implementations
// ──────────────────────────────────────────────────────────────────────────────

fn mut_add_split_coins<R: Rand>(rng: &mut R, ptb: &mut ProgrammableTransaction) {
    // Ensure there's at least one pure input to supply the amount.
    if ptb.inputs.is_empty() {
        ptb.inputs.push(pure_u64(1000));
    }
    let input_idx = rand_idx(rng, ptb.inputs.len()).unwrap_or(0) as u16;
    ptb.commands.push(Command::SplitCoins(
        Argument::GasCoin,
        vec![Argument::Input(input_idx)],
    ));
}

fn mut_add_merge_coins<R: Rand>(rng: &mut R, ptb: &mut ProgrammableTransaction) {
    let n = ptb.commands.len();
    if n == 0 {
        return;
    }
    let src = rand_idx(rng, n).unwrap() as u16;
    ptb.commands.push(Command::MergeCoins(
        Argument::GasCoin,
        vec![Argument::Result(src)],
    ));
}

fn mut_add_make_move_vec<R: Rand>(rng: &mut R, ptb: &mut ProgrammableTransaction) {
    if ptb.inputs.is_empty() {
        ptb.inputs.push(pure_u64(0));
    }
    let input_idx = rand_idx(rng, ptb.inputs.len()).unwrap_or(0) as u16;
    ptb.commands.push(Command::MakeMoveVec(
        Some(TypeInput::U64),
        vec![Argument::Input(input_idx)],
    ));
}

fn mut_dup_command<R: Rand>(rng: &mut R, ptb: &mut ProgrammableTransaction) {
    if let Some(i) = rand_idx(rng, ptb.commands.len()) {
        let cloned = ptb.commands[i].clone();
        ptb.commands.push(cloned);
    }
}

fn mut_swap_commands<R: Rand>(rng: &mut R, ptb: &mut ProgrammableTransaction) {
    let n = ptb.commands.len();
    if n < 2 {
        return;
    }
    let a = rng.below(NonZeroUsize::new(n).unwrap());
    let mut b = rng.below(NonZeroUsize::new(n).unwrap());
    if b == a {
        b = (b + 1) % n;
    }
    ptb.commands.swap(a, b);
}

fn mut_remove_command<R: Rand>(rng: &mut R, ptb: &mut ProgrammableTransaction) {
    if let Some(i) = rand_idx(rng, ptb.commands.len()) {
        ptb.commands.remove(i);
    }
}

fn mut_add_pure_input(ptb: &mut ProgrammableTransaction) {
    ptb.inputs.push(pure_u64(42));
}

fn mut_remove_input<R: Rand>(rng: &mut R, ptb: &mut ProgrammableTransaction) {
    // Only remove if there's more than one input to avoid leaving commands dangling on nothing.
    if ptb.inputs.len() > 1 {
        if let Some(i) = rand_idx(rng, ptb.inputs.len()) {
            ptb.inputs.remove(i);
        }
    }
}

/// Replace one Argument inside a random command with GasCoin, Input(i), Result(n), or
/// NestedResult(n,j). Including Result/NestedResult is important for exercising command
/// chaining inside the typing pass.
fn mut_scramble_argument<R: Rand>(rng: &mut R, ptb: &mut ProgrammableTransaction) {
    // Collect (cmd_idx, arg_idx) pairs for every mutable Argument slot.
    let slots: Vec<(usize, usize)> = ptb
        .commands
        .iter()
        .enumerate()
        .flat_map(|(ci, cmd)| {
            let n = match cmd {
                Command::MoveCall(mc) => mc.arguments.len(),
                Command::TransferObjects(args, _) => args.len(),
                Command::SplitCoins(_, amounts) => amounts.len() + 1,
                Command::MergeCoins(_, coins) => coins.len() + 1,
                Command::MakeMoveVec(_, args) => args.len(),
                Command::Publish(_, _) | Command::Upgrade(_, _, _, _) => 0,
            };
            (0..n).map(move |ai| (ci, ai))
        })
        .collect();

    if let Some(slot_i) = rand_idx(rng, slots.len()) {
        let (ci, ai) = slots[slot_i];
        let n_cmds = ptb.commands.len() as u16;
        let n_inputs = ptb.inputs.len() as u16;
        // 4 classes of argument; bias toward Result when there are prior commands.
        let replacement = match rng.below(NonZeroUsize::new(4).unwrap()) {
            0 => Argument::GasCoin,
            1 => Argument::Input(if n_inputs > 0 {
                rng.below(NonZeroUsize::new(n_inputs as usize).unwrap()) as u16
            } else {
                0
            }),
            2 if n_cmds > 0 => {
                Argument::Result(rng.below(NonZeroUsize::new(n_cmds as usize).unwrap()) as u16)
            }
            3 if n_cmds > 0 => Argument::NestedResult(
                rng.below(NonZeroUsize::new(n_cmds as usize).unwrap()) as u16,
                rng.below(NonZeroUsize::new(8).unwrap()) as u16,
            ),
            _ => Argument::GasCoin,
        };
        match &mut ptb.commands[ci] {
            Command::MoveCall(mc) => mc.arguments[ai] = replacement,
            Command::TransferObjects(args, dest) => {
                if ai < args.len() {
                    args[ai] = replacement;
                } else {
                    *dest = replacement;
                }
            }
            Command::SplitCoins(coin, amounts) => {
                if ai == 0 {
                    *coin = replacement;
                } else {
                    amounts[ai - 1] = replacement;
                }
            }
            Command::MergeCoins(coin, rest) => {
                if ai == 0 {
                    *coin = replacement;
                } else {
                    rest[ai - 1] = replacement;
                }
            }
            Command::MakeMoveVec(_, args) => args[ai] = replacement,
            Command::Publish(_, _) | Command::Upgrade(_, _, _, _) => {}
        }
    }
}

/// Repeat the argument list of a random command several times (stresses argument-splatting).
fn mut_fan_out_args<R: Rand>(rng: &mut R, ptb: &mut ProgrammableTransaction) {
    let n = ptb.commands.len();
    if n == 0 {
        return;
    }
    let factor = rng.between(2, 8);
    let ci = rng.below(NonZeroUsize::new(n).unwrap());
    match &mut ptb.commands[ci] {
        Command::MoveCall(mc) => {
            let base = mc.arguments.clone();
            for _ in 1..factor {
                mc.arguments.extend_from_slice(&base);
            }
        }
        Command::MakeMoveVec(_, args) => {
            let base = args.clone();
            for _ in 1..factor {
                args.extend_from_slice(&base);
            }
        }
        Command::TransferObjects(args, _) => {
            let base = args.clone();
            for _ in 1..factor {
                args.extend_from_slice(&base);
            }
        }
        Command::MergeCoins(_, coins) => {
            let base = coins.clone();
            for _ in 1..factor {
                coins.extend_from_slice(&base);
            }
        }
        Command::SplitCoins(_, amounts) => {
            let base = amounts.clone();
            for _ in 1..factor {
                amounts.extend_from_slice(&base);
            }
        }
        Command::Publish(_, _) | Command::Upgrade(_, _, _, _) => {}
    }
}

/// Append a chain of `depth` MakeMoveVec commands, each wrapping the previous
/// result in a deeper `vector<…>` — stresses Path::extensions cloning.
fn mut_deep_result_chain<R: Rand>(rng: &mut R, ptb: &mut ProgrammableTransaction) {
    let depth = rng.between(4, 16);
    let start_cmd = ptb.commands.len();

    // Anchor: need at least one existing command to chain from, or add one.
    if start_cmd == 0 {
        if ptb.inputs.is_empty() {
            ptb.inputs.push(pure_u64(0));
        }
        ptb.commands.push(Command::MakeMoveVec(
            Some(TypeInput::U64),
            vec![Argument::Input(0)],
        ));
    }

    for i in 0..depth {
        let src_cmd = (start_cmd + i) as u16;
        let ty = nested_vector_type(i as u32 + 1);
        ptb.commands.push(Command::MakeMoveVec(
            Some(ty),
            vec![Argument::Result(src_cmd)],
        ));
    }
}

fn nested_vector_type(depth: u32) -> TypeInput {
    let mut t = TypeInput::U64;
    for _ in 0..depth {
        t = TypeInput::Vector(Box::new(t));
    }
    t
}

/// Insert a MoveCall to a known-valid function drawn from a static table covering
/// the fuzz-fixture package and key framework entry points in `0x2::coin` /
/// `0x2::object` / `0x2::transfer`.  All entries are resolvable by the fixture
/// store, so the input will reach the loading/typing passes instead of dying at
/// linkage.  Arguments are set to `GasCoin` / `Input(0)` / `Result(prev)` in
/// whatever combination satisfies the arity — the typing pass will reject bad
/// types, which is expected and fine; what matters is reaching the pass at all.
fn mut_add_move_call<R: Rand>(rng: &mut R, ptb: &mut ProgrammableTransaction) {
    // (package_hex, module, function, num_ty_args, num_args)
    // num_ty_args: how many TypeInput::U64 type arguments to supply.
    // num_args: how many Argument slots to fill (typing will reject wrong types).
    const FUNCS: &[(&str, &str, &str, usize, usize)] = &[
        // fuzz_fixture — no type args
        (ADDRESS, MODULE, "nothing", 0, 0),
        (ADDRESS, MODULE, "take_u8", 0, 1),
        (ADDRESS, MODULE, "take_u64", 0, 1),
        (ADDRESS, MODULE, "take_u128", 0, 1),
        (ADDRESS, MODULE, "take_u256", 0, 1),
        (ADDRESS, MODULE, "take_bool", 0, 1),
        (ADDRESS, MODULE, "take_address", 0, 1),
        (ADDRESS, MODULE, "take_vec_u64", 0, 1),
        (ADDRESS, MODULE, "take_vec_address", 0, 1),
        (ADDRESS, MODULE, "use_imm_ref", 0, 1),
        (ADDRESS, MODULE, "use_mut_ref", 0, 1),
        (ADDRESS, MODULE, "new_box", 0, 1),
        (ADDRESS, MODULE, "unbox", 0, 1),
        (ADDRESS, MODULE, "box_value", 0, 1),
        (ADDRESS, MODULE, "two_values", 0, 0),
        (ADDRESS, MODULE, "take_key_box", 0, 1),
        (ADDRESS, MODULE, "key_box_value", 0, 1),
        (ADDRESS, MODULE, "receive_sui_coin", 0, 2),
        (ADDRESS, MODULE, "receive_key_box", 0, 2),
        (ADDRESS, MODULE, "private_non_entry", 0, 1),
        (ADDRESS, MODULE, "private_take_u64", 0, 1),
        (ADDRESS, MODULE, "make_hot_potato", 0, 0),
        (ADDRESS, MODULE, "two_hot_potatoes", 0, 0),
        (ADDRESS, MODULE, "take_hot_potato", 0, 1),
        // fuzz_fixture — with type args
        (ADDRESS, MODULE, "identity", 1, 1),
        (ADDRESS, MODULE, "ignore", 1, 1),
        (ADDRESS, MODULE, "make_pair", 1, 2),
        (ADDRESS, MODULE, "swap", 1, 2),
        // 0x2::coin
        ("0x2", "coin", "value", 1, 1),
        ("0x2", "coin", "zero", 1, 0),
        ("0x2", "coin", "join", 1, 2),
        ("0x2", "coin", "split", 1, 2),
        ("0x2", "coin", "destroy_zero", 1, 1),
        // 0x2::object
        ("0x2", "object", "id_address", 0, 1),
        // 0x2::transfer
        ("0x2", "transfer", "public_freeze_object", 1, 1),
        ("0x2", "transfer", "public_share_object", 1, 1),
        ("0x2", "transfer", "transfer", 1, 2),
    ];

    let choice = rng.below(NonZeroUsize::new(FUNCS.len()).unwrap());
    let (pkg_hex, module, function, num_ty_args, num_args) = FUNCS[choice];

    let package = ObjectID::from_hex_literal(pkg_hex).unwrap_or(ObjectID::ZERO);

    let type_arguments: Vec<TypeInput> = (0..num_ty_args).map(|_| TypeInput::U64).collect();

    // Build an argument list: prefer existing Results for chaining, fall back to GasCoin.
    let n_cmds = ptb.commands.len() as u16;
    let arguments: Vec<Argument> = (0..num_args)
        .map(|i| {
            if n_cmds > 0 && i == 0 {
                // Use the most recent result as the first argument to encourage chaining.
                Argument::Result(n_cmds - 1)
            } else {
                Argument::GasCoin
            }
        })
        .collect();

    ptb.commands
        .push(Command::MoveCall(Box::new(ProgrammableMoveCall {
            package,
            module: module.to_string(),
            function: function.to_string(),
            type_arguments,
            arguments,
        })));
}

/// Wrap the first type-argument of a random MoveCall one level deeper in `vector<>`.
fn mut_nest_type_arg<R: Rand>(rng: &mut R, ptb: &mut ProgrammableTransaction) {
    let move_calls: Vec<usize> = ptb
        .commands
        .iter()
        .enumerate()
        .filter_map(|(i, cmd)| {
            if let Command::MoveCall(mc) = cmd {
                if !mc.type_arguments.is_empty() {
                    Some(i)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    if let Some(slot) = rand_idx(rng, move_calls.len()) {
        let ci = move_calls[slot];
        if let Command::MoveCall(mc) = &mut ptb.commands[ci] {
            let inner = mc.type_arguments[0].clone();
            mc.type_arguments[0] = TypeInput::Vector(Box::new(inner));
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Public mutator struct
// ──────────────────────────────────────────────────────────────────────────────

const NUM_OPS: usize = 13;

pub struct PtbMutator;

impl<S> Mutator<BytesInput, S> for PtbMutator
where
    S: libafl::state::HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let bytes = input.target_bytes();
        let Ok(mut ptb) = bcs::from_bytes::<ProgrammableTransaction>(&*bytes) else {
            return Ok(MutationResult::Skipped);
        };

        let op = state.rand_mut().below(NonZeroUsize::new(NUM_OPS).unwrap());

        let rng = state.rand_mut();
        match op {
            0 => mut_add_split_coins(rng, &mut ptb),
            1 => mut_add_merge_coins(rng, &mut ptb),
            2 => mut_add_make_move_vec(rng, &mut ptb),
            3 => mut_dup_command(rng, &mut ptb),
            4 => mut_swap_commands(rng, &mut ptb),
            5 => mut_remove_command(rng, &mut ptb),
            6 => mut_add_pure_input(&mut ptb),
            7 => mut_remove_input(rng, &mut ptb),
            8 => mut_scramble_argument(rng, &mut ptb),
            9 => mut_fan_out_args(rng, &mut ptb),
            10 => mut_deep_result_chain(rng, &mut ptb),
            11 => mut_nest_type_arg(rng, &mut ptb),
            12 => mut_add_move_call(rng, &mut ptb),
            _ => unreachable!(),
        }

        match bcs::to_bytes(&ptb) {
            Ok(new_bytes) => {
                *input = BytesInput::new(new_bytes);
                Ok(MutationResult::Mutated)
            }
            // Re-serialization should never fail for well-typed data; treat as skipped.
            Err(_) => Ok(MutationResult::Skipped),
        }
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for PtbMutator {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        static NAME: std::borrow::Cow<'static, str> = std::borrow::Cow::Borrowed("PtbMutator");
        &NAME
    }
}
