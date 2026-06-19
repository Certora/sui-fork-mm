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
//! 8  ScrambleArgument     replace one Argument in a random command with GasCoin / Input(0)
//! 9  FanOutArgs           repeat the argument list of a random command N times (stress splatting)
//! 10 DeepResultChain      append a chain of MakeMoveVec wrapping the last result (stress Path clone)
//! 11 NestTypeArg          wrap the first type-arg of a random MoveCall one level deeper in vector<>

use std::num::NonZeroUsize;

use libafl::{
    corpus::CorpusId,
    inputs::{BytesInput, HasTargetBytes},
    mutators::{MutationResult, Mutator},
    Error,
};
use libafl_bolts::{Named, rands::Rand};
use sui_types::{
    transaction::{Argument, CallArg, Command, ProgrammableTransaction},
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

/// Replace one Argument inside a random command with either GasCoin or Input(0).
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
        let replacement = if rng.below(NonZeroUsize::new(2).unwrap()) == 0 {
            Argument::GasCoin
        } else {
            Argument::Input(0)
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

const NUM_OPS: usize = 12;

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

        let op = state
            .rand_mut()
            .below(NonZeroUsize::new(NUM_OPS).unwrap());

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
