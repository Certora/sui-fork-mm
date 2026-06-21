// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate sui_types;

pub mod adapter;
pub mod data_store;
pub mod error;
// The full transaction driver is only reachable through the production `Executor`
// entry, which the typing fuzz harness never invokes (it drives the pipeline
// directly up to `typing::translate_and_verify`). Compiling it out under
// `--cfg=fuzzing` keeps ~2k lines of unreachable code out of the sancov
// instrumentation so the edge denominator reflects the typing pipeline only.
#[cfg(not(fuzzing))]
pub mod execution_engine;
pub mod execution_mode;
pub mod execution_value;
pub mod gas_charger;
pub mod gas_meter;
pub mod static_programmable_transactions;
// `temporary_store` (the per-transaction mutable object store) and
// `type_layout_resolver` are only exercised by the interpreter/effects path. The
// typing fuzz harness supplies its own minimal, uninstrumented `ExecutionState`
// (see `fixture.rs`) that delegates reads to the framework store, so both are
// compiled out under `--cfg=fuzzing` to drop ~1.8k more lines from instrumentation.
#[cfg(not(fuzzing))]
pub mod temporary_store;
#[cfg(not(fuzzing))]
pub mod type_layout_resolver;
