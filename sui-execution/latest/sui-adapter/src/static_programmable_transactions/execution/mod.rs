// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// The interpreter and everything that only it touches (`context`, `values`,
// `trace_utils`) are the runtime tail of the pipeline. The typing fuzz harness
// stops at `typing::translate_and_verify` and never runs them, so they are
// compiled out under `--cfg=fuzzing` to keep ~3.5k lines of unreachable code out
// of sancov instrumentation. The handful of items the loading/typing pass needs
// from the old `context` module live in the always-compiled `typing_support`.
#[cfg(not(fuzzing))]
pub mod context;
#[cfg(not(fuzzing))]
pub mod interpreter;
#[cfg(not(fuzzing))]
mod trace_utils;
pub mod typing_support;
#[cfg(not(fuzzing))]
pub mod values;
