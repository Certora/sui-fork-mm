#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# rustc-wrapper: inject sancov instrumentation flags ONLY for sui_adapter_latest.
#
# Used via [build] rustc-wrapper in .cargo/config.toml.  CARGO_CRATE_NAME is set
# by Cargo before invoking rustc so we can gate the flags on the specific crate.
# Without this scoping, the entire dependency closure (~183K edges) is instrumented
# and MaxMapFeedback saturates in the first minute; with it, only the typing pipeline
# is instrumented (~few hundred edges), making every new branch a real corpus event.
#
# --cfg=fuzzing is applied to all crates (required for conditional compilation in
# sui-adapter-latest that gates fuzz-only code paths).

RUSTC="$1"
shift

if [ "$CARGO_CRATE_NAME" = "sui_adapter_latest" ]; then
    exec "$RUSTC" "$@" \
        -Cpasses=sancov-module \
        "-Cllvm-args=-sanitizer-coverage-level=4" \
        "-Cllvm-args=-sanitizer-coverage-trace-pc-guard" \
        --cfg=fuzzing
else
    exec "$RUSTC" "$@" --cfg=fuzzing
fi
