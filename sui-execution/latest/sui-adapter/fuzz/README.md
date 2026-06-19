# translate\_and\_verify fuzzing campaign

Fuzzing harness for `typing::translate_and_verify` — the pipeline stage that
takes a loaded PTB AST and produces a fully-typed, verified one, stopping just
before the Move interpreter runs.

## What we are hunting

Panics, `invariant_violation!` aborts, and OOM kills triggered by
pathological-but-structurally-valid `ProgrammableTransaction` inputs.
A returned `Err(_)` is the **normal** outcome for most fuzz inputs and is not a
finding.

## Running

```sh
# 1. Build from inside fuzz/ — REQUIRED for sancov instrumentation.
#    The .cargo/config.toml that injects the coverage flags is CWD-based;
#    building from the repo root silently skips it and produces an
#    uninstrumented binary (edges: 0/2097152, corpus grows from TimeFeedback only).
cd sui-execution/latest/sui-adapter/fuzz

cargo build --release --bin gen_corpus
cargo build --release --bin translate_and_verify

# 2. Workspace
mkdir -p /path/to/fuzz-test
cp target/x86_64-unknown-linux-gnu/release/{gen_corpus,translate_and_verify} /path/to/fuzz-test/
cd /path/to/fuzz-test

# 3. Generate the corpus
./gen_corpus
```

> **Verify instrumentation:** at startup the fuzzer should report a non-zero edge
> count well below 2M, e.g. `edges: 85/183339 (0%)`.  If you see `edges: 0/2097152`
> the binary was built without sancov — rebuild from inside `fuzz/`.

> **macOS users:** `.cargo/config.toml` hard-codes `target = "x86_64-unknown-linux-gnu"`.
> Change it to match your host before building, e.g. `aarch64-apple-darwin` for Apple
> Silicon or `x86_64-apple-darwin` for Intel Macs.  Update the binary path in the
> commands below accordingly.

### Re-calibrating the RSS threshold (recommended before a full campaign)

The compile-time constant `RSS_DELTA_LIMIT_BYTES` is a seed-based estimate
(5× the worst corpus seed).  Tighten it against real fuzz traffic in two steps:

**Step 0 — verify the typing pass is being reached**

Before collecting RSS deltas it is worth confirming that fuzz inputs are
actually reaching `typing::translate_and_verify` and not failing earlier (e.g.
at linkage because they reference packages absent from the fixture store).

```sh
timeout 2m ./translate_and_verify --record-stages
```

Every ~15 seconds the monitor prints a breakdown to stderr:

```
[stages] n=30000  decode_fail=12.3%  linkage_fail=85.1%  loading_fail=1.8%  typing_reached=0.8%
```

If `typing_reached` is near zero the corpus seeds or mutator need adjustment
before a full campaign is worthwhile.

**Step 1 — collect the distribution (~10 minutes)**

```sh
timeout 10m ./translate_and_verify --record-deltas
```

Appends one RSS-delta value per iteration to `./rss_deltas.log`.

**Step 2 — apply the derived threshold**

```sh
./translate_and_verify --rss-threshold-from rss_deltas.log
```

Reads `rss_deltas.log`, computes p99.9 × 1.5 (rounded up to the nearest MiB),
prints the derived value to stderr, and uses it as the runtime limit for this
run — no source edit required.  Both flags can be combined to record and apply
simultaneously:

```sh
./translate_and_verify --record-deltas --rss-threshold-from rss_deltas.log
```

After calibration, pass `--rss-threshold-from rss_deltas.log` on every run to
apply the derived threshold automatically.  If you want to avoid repeating the
flag, update `RSS_DELTA_LIMIT_BYTES` in `translate_and_verify.rs` to bake the
value in as the compile-time default and rebuild.

Interesting corpus entries accumulate in `./corpus/`.
Crashes and timeouts are saved to `./crashes/`.

---

## Corpus generator (`gen_corpus`)

`gen_corpus` produces BCS-serialized `ProgrammableTransaction` files that give
the fuzzer structurally valid starting points.  Random bytes almost never
decode as a valid PTB, so without a seed corpus the fuzzer spends nearly all
its time on inputs that are rejected at the BCS layer before any interesting
code is reached.

Each seed is a hand-crafted worst case for a specific code path in the typing
pipeline.

| File | Strategy | What it stresses |
|------|----------|-----------------|
| `01_minimal_transfer` | Single `TransferObjects(GasCoin, addr)` | Baseline — confirms the fixture initialises correctly and a well-formed PTB passes all checks |
| `02_empty_ptb` | Zero inputs, zero commands | Edge: empty-collection handling throughout the pipeline |
| `03_split_merge_chain_512` | 512 alternating `SplitCoins`/`MergeCoins` pairs (1024 commands total) | `invariant_checks::memory_safety`: each pair extends the reference derivation chain (`Path::extensions` cloning), producing O(n) `Vec<Delta>` growth |
| `04_make_move_vec_fan_out_255` | One `MakeMoveVec` command with 255 identical arguments | `translate::Context` argument-splatting and the O(#args) result-accumulation loop |
| `05_deep_result_chain_64` | 64 `MakeMoveVec` commands, each wrapping the previous result in a deeper `vector<…>` type | `Path::extensions` clone depth; each step adds a derivation delta to the chain of the final result |
| `06_deep_type_args_16` | `MoveCall` with a type argument nested 16 levels deep (`Coin<Coin<…<SUI>…>>`) | `metering::typing` type-node counting on maximally nested types; hits `max_type_argument_depth` |
| `07_wide_type_args_16` | `MoveCall` with 16 distinct type arguments | Type-argument width validation and per-argument metering |
| `08_max_pure_multi_use_64` | A single 16 KiB pure input referenced by 64 commands | `IndexSet` bytes-interning growth; type-inference paths that re-evaluate the same pure input against different expected types |
| `09_nested_result_crossref_512` | 512-command linear `NestedResult` chain — each command references the previous via `NestedResult(i, 0)` | Out-of-bounds path in `translate::Context::locations()`; `NestedResult` index handling |
| `10_transfer_fan_in_255` | 255 `SplitCoins` results collected by one `TransferObjects` | Many-input memory-safety tracking; argument-count validation |

The seeds above (01–10) include `MoveCall` commands referencing the Sui framework package, which fail at the loading pass because the fixture store only contains system packages — not arbitrary on-chain objects.  The seeds below (11–16) use **only** `SplitCoins`, `MergeCoins`, `MakeMoveVec` (with primitive types), and `TransferObjects`, so they pass the loading pass entirely and exercise deeper paths in the typing pass.  They also introduce `NestedResult` sub-indexing, which none of the original seeds cover.

| File | Strategy | What it stresses |
|------|----------|-----------------|
| `11_split_many_amounts_255` | `SplitCoins(GasCoin, [amt]*255)` — one command producing 255 sub-results | Multi-return result sub-index handling; result-type `Vec` capacity for wide single commands |
| `12_nested_result_fan_in_64` | `SplitCoins` producing 64 sub-results, all collected by `TransferObjects` via `NestedResult(0, i)` | `NestedResult` sub-index validation across a wide range; borrow-tracking of many independently derived coin references |
| `13_split_chain_256` | 256-deep chain of `SplitCoins` each consuming the previous result | Linear mutable-borrow derivation; `Path::extensions` growth through a chained coin type |
| `14_make_vec_primitives` | Three `MakeMoveVec` commands over `Bool`, `U8`, and `Address` pure inputs (32 args each) | Primitive type unification; pure-input interning across different expected types |
| `15_merge_split_cycle` | `SplitCoins` → `MergeCoins` → `SplitCoins` → `MergeCoins` interleaved on `NestedResult` and `Result` references | Borrow-graph path convergence; coins merged then re-split, testing the memory-safety pass on non-linear derivation chains |
| `16_split_max_width_boundary` | `SplitCoins(GasCoin, [amt]*255)` followed by `TransferObjects` referencing sub-indices 0 and 254 (boundary values) | Maximum sub-result index validation; `u16` boundary near 255 |

---

## Structure-aware mutator (`PtbMutator`)

The default LibAFL havoc mutations operate at the byte level.  Once the corpus
contains valid BCS-encoded PTBs, havoc mutations immediately corrupt the BCS
framing (length prefixes, enum discriminants), producing inputs that are
rejected before reaching the target.  `PtbMutator` fixes this by mutating at
the `ProgrammableTransaction` type level: deserialise → mutate → re-serialise.
BCS validity is preserved by construction.

`PtbMutator` is prepended to the havoc stack.  If the current input does not
decode as a valid PTB it returns `Skipped` and havoc handles it as raw bytes.

### Mutation table

| Op | Description | Target hotspot |
|----|-------------|----------------|
| `AddSplitCoins` | Insert `SplitCoins(GasCoin, [Input(i)])` at end | Borrow chain growth in `memory_safety` |
| `AddMergeCoins` | Insert `MergeCoins(GasCoin, [Result(prev)])` at end | `Path::extensions` cloning |
| `AddMakeMoveVec` | Insert `MakeMoveVec(U64, [Input(i)])` at end | Result-accumulation scaling |
| `DupCommand` | Clone a random command and append it | Command-count scaling |
| `SwapCommands` | Swap two random commands | Index-validity paths after reordering |
| `RemoveCommand` | Drop a random command | Dangling-result and empty-command handling |
| `AddPureInput` | Append a fresh pure-u64 input | Input-count scaling; bytes-interning (`IndexSet` growth) |
| `RemoveInput` | Drop a random input (only when >1 exist) | Input-index bounds checks |
| `ScrambleArgument` | Replace one argument in a random command with `GasCoin` or `Input(0)` | Type-mismatch error paths; unexpected argument kinds |
| `FanOutArgs` | Repeat a command's argument list 2–8× | Argument-splatting O(n) path in `translate::Context` |
| `DeepResultChain` | Append 4–16 `MakeMoveVec` commands each wrapping the previous result | `Path::extensions` clone depth; derivation-chain memory growth |
| `NestTypeArg` | Wrap the first type argument of a random `MoveCall` one level deeper in `vector<>` | Type-node count in `metering::typing`; `max_type_argument_depth` boundary |

### Feedback

| Signal | Purpose |
|--------|---------|
| `MaxMapFeedback` (edge coverage) | Standard coverage-guided novelty — keeps inputs that reach new code |
| `TimeFeedback` | Keeps inputs that take longer than average even without new coverage, steering toward allocation-heavy paths |
| `CrashFeedback` | Detects panics and `invariant_violation!` aborts in the child process |
| `TimeoutFeedback` (500 ms limit) | OOM-triggering inputs typically manifest as timeouts before the kernel OOM-kills the child |
| `NewHashFeedback` (backtrace dedup) | A crash/timeout is only saved to `./crashes/` if its backtrace hash is new — prevents the crash corpus filling with thousands of inputs that all hit the same allocation path |

### Executor and OOM isolation

The fuzzer uses `InProcessForkExecutor`: the parent process forks before each
iteration and the harness runs in the child.  An OOM kill (`SIGKILL`) in the
child does not affect the fuzzer — the parent catches `SIGCHLD`, records the
exit status, and continues.

An RSS delta guard reads `VmRSS` from `/proc/self/status` before and after each
harness call (unlike `getrusage`, which returns a peak-ever value on Linux and
produces a zero delta).  Any input that causes net allocation above
`RSS_DELTA_LIMIT_BYTES` is treated as a crash and saved to `./crashes/`.
Because all RSS-triggered findings share an empty backtrace, `NewHashFeedback`
deduplicates them to a single saved file.

The threshold is set empirically: `gen_corpus` runs each seed through the real
pipeline, reports the RSS delta per file, and suggests **5× the worst-case
observed value**.  The seeds are already hand-crafted extremes, so a legitimate
fuzz mutation is unlikely to allocate more than a few multiples of the worst
seed; 5× leaves headroom without being so generous that anomalous inputs go
undetected.  As of the current seed set the worst case is
`04_make_move_vec_fan_out_255` at ~12.3 MiB, giving a threshold of **62 MiB**.

This is a starting-point estimate.  After a warm-up run of ~10 minutes,
re-calibrate by plotting the actual RSS-delta distribution across all inputs
that reached `run_typing` and tighten the threshold to the 99.9th percentile
plus one multiplier step.
