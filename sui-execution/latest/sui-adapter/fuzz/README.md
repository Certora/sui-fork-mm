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
#    The .cargo/config.toml and rustc_sancov_wrapper.sh that inject the coverage
#    flags are CWD-based; building from the repo root silently skips them and
#    produces an uninstrumented binary (edges: 0/2097152).
cd sui-execution/latest/sui-adapter/fuzz

cargo build --release --bin gen_corpus
cargo build --release --bin translate_and_verify

# 2. Workspace
mkdir -p /path/to/fuzz-test
cp target/x86_64-unknown-linux-gnu/release/{gen_corpus,translate_and_verify} /path/to/fuzz-test/
cd /path/to/fuzz-test

# 3. Generate the corpus
./gen_corpus

# 4. Run
./translate_and_verify
```

> **Verify instrumentation:** at startup the fuzzer should report a non-zero edge
> count in the thousands, e.g. `edges: 1425/8681 (16%)`.  If you see
> `edges: 0/2097152` the binary was built without sancov — rebuild from inside
> `fuzz/`.  If you see `edges: 0/8681` the sancov wrapper is active but
> `InProcessExecutor` is not writing back edge hits — check that the binary was
> not accidentally built with `InProcessForkExecutor`.

> **macOS users:** `rustc_sancov_wrapper.sh` and `.cargo/config.toml` hard-code
> `target = "x86_64-unknown-linux-gnu"`.  Change the target triple to match your
> host before building, e.g. `aarch64-apple-darwin` for Apple Silicon or
> `x86_64-apple-darwin` for Intel Macs.  Update the binary path in the copy
> command above accordingly.

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
apply the derived threshold automatically.  If you want to bake the value in
permanently, update `RSS_DELTA_LIMIT_BYTES` in `translate_and_verify.rs` and
rebuild.

Interesting corpus entries accumulate in `./corpus/`.
Crashes and timeouts are saved to `./crashes/`.

---

## Triaging the crashes directory

After a campaign the `./crashes/` directory contains every input that triggered
the objective (crash, timeout, or RSS overage) with a unique backtrace hash.
Not all of them are real bugs.  Use the `replay` binary to distinguish genuine
findings from noise quickly.

```sh
# Build the replay tool (same build step as the fuzzer itself)
cd sui-execution/latest/sui-adapter/fuzz
cargo build --release --bin replay

cp target/x86_64-unknown-linux-gnu/release/replay /path/to/fuzz-test/
cd /path/to/fuzz-test
```

Run it against the whole directory:

```sh
./replay crashes/
```

Output is one line per file:

```
file                                                            bytes  stage         anon_rss∆   wall_ms
----------------------------------------------------------------------------------------------------------
e101a7f8bedac268                                             1260376  typing_ok        9.3 MiB        24
9eb9b79caa72d02d                                               1424  decode_fail      0.0 MiB         0
...
```

**Interpreting the columns:**

| Column | Meaning |
|--------|---------|
| `stage` | Where the pipeline stopped: `decode_fail` (BCS parse error), `linkage_fail`, `loading_fail`, or `typing_ok` (reached and completed translate_and_verify) |
| `anon_rss∆` | Net change in anonymous RSS (heap + stack only) over the iteration — a proxy for per-input allocation |
| `wall_ms` | Wall-clock time for the iteration |
| `*** PANIC ***` | The input triggered a panic or `invariant_violation!` — a real finding |
| `*** RSS ***` | `anon_rss∆` exceeded 62 MiB — a potential OOM finding |

**What to look for:**

- Any line with `*** PANIC ***` is a real bug.  Replay that single file to get the full backtrace:
  ```sh
  RUST_BACKTRACE=1 ./replay crashes/<hash>
  ```
- Lines where `stage = decode_fail` or `loading_fail` are almost certainly false positives — the input never reached the target.
- `typing_ok` with low `anon_rss∆` and short `wall_ms` that re-runs cleanly indicates the objective was triggered by RSS baseline drift during a long in-process campaign (the `VmRSS` snapshot before the iteration was elevated by shared memory accumulation, making the delta look larger than it was).  These are not findings.
- High `anon_rss∆` values (≫ the 62 MiB threshold) on `typing_ok` inputs that don't panic are worth investigating: they indicate the typing pass allocates pathologically on certain input shapes even without crashing.

**Prioritisation:**

```sh
# Panics first
grep 'PANIC' <(./replay crashes/)

# Then large anon RSS on typing_ok inputs
./replay crashes/ | awk '$3=="typing_ok" {gsub(/MiB/,""); if ($4+0 > 20) print}' | sort -k4 -rn

# Ignore decode_fail and loading_fail entirely
./replay crashes/ | grep -v 'decode_fail\|loading_fail'
```

### Known false-positive pattern: RSS baseline drift

`InProcessExecutor` runs the harness in the same process across all iterations.
Over a long campaign the process RSS grows steadily: the corpus accumulates in
memory, LibAFL's shared-memory edge map and backtrace observer expand, and the
Rust allocator's free lists grow.  If the per-iteration delta is measured
against the live RSS (`VmRSS`), this baseline drift is baked into the "before"
snapshot, inflating small legitimate allocations into apparent threshold
violations.

The harness now measures `RssAnon` (private anonymous pages only) rather than
`VmRSS`.  `VmRSS = RssAnon + RssFile + RssShmem`; the file-backed and
shared-memory components fluctuate with kernel paging activity and accumulate
with LibAFL's own shared-memory segments independently of anything the input
causes.  `RssAnon` eliminates those two components.  It does not give a
perfectly isolated view of harness-only allocations — the Rust allocator's
free lists are also anonymous heap pages and grow over time — but the delta is
measured tightly within the harness closure, so LibAFL's own per-iteration
allocations (which run outside the closure) are excluded.  The result is
significantly less drift than `VmRSS`, not zero drift.

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
| `CrashFeedback` | Detects panics and `invariant_violation!` aborts |
| `TimeoutFeedback` (500 ms limit) | OOM-triggering inputs typically manifest as timeouts before the process hits the virtual-memory ceiling |
| `NewHashFeedback` (backtrace dedup) | Combined with `EagerAndFeedback`: a finding is saved **only if** it is a crash/timeout **and** its backtrace hash is new — both conditions must hold |

### Executor and OOM isolation

The fuzzer uses `InProcessExecutor` with a 500 ms timeout.  Running in-process
means the static `EDGES_MAP` written by the sancov hooks is directly visible to
`MaxMapFeedback` in the same process — no copy-on-write gap.

OOM isolation is provided by `setrlimit(RLIMIT_AS, 4 GiB)` set at startup.
When an input exhausts virtual address space, `mmap` returns `ENOMEM`, Rust's
allocator calls `abort()`, and LibAFL's in-process `SIGABRT` handler catches
the signal as `ExitKind::Crash`, saves the input to `./crashes/`, and continues
fuzzing.  The 4 GiB ceiling is well above any legitimate PTB; the RSS delta
guard provides the finer-grained signal for moderate over-allocation.

> **Why not `InProcessForkExecutor`?**  Fork-based execution isolates each
> iteration in a child process, but the child inherits the static `EDGES_MAP`
> as a copy-on-write page.  Any sancov writes in the child go to the child's
> private copy and are never visible to the parent's `MaxMapFeedback`.  The
> result is permanently `edges: 0/N` — coverage signal is completely lost.

### Coverage scoping

`rustc_sancov_wrapper.sh` is invoked as `rustc-wrapper` by `.cargo/config.toml`.
It adds the sancov flags (`-Cpasses=sancov-module`,
`-sanitizer-coverage-trace-pc-guard`, etc.) **only** when compiling the
`sui_adapter_latest` crate, and passes `--cfg=fuzzing` to all crates.

Without scoping, the full dependency closure (~183K edges) is instrumented.
The 85 edges that are ever reached belong to fixture-initialisation code in
dependency crates, and `MaxMapFeedback` saturates in the first minute.  With
scoping, only the typing pipeline is instrumented (~8681 edges), making every
new branch in `translate_and_verify` a genuine corpus event.

### RSS delta guard

An RSS delta guard reads `RssAnon` from `/proc/self/status` before and after
each harness call.  `RssAnon` covers only private anonymous pages (heap +
stack), so it excludes two sources of noise that `VmRSS` picks up:
file-backed pages (`RssFile`) paged in/out by the kernel on its own schedule,
and shared-memory segments (`RssShmem`) — LibAFL's edge map and backtrace
observer live here and accumulate steadily over a long in-process run.
Using `VmRSS` causes baseline drift: the "before" snapshot is already elevated
by those accumulated shared pages, inflating small legitimate allocations into
apparent threshold violations.

`RssAnon` is not a perfectly isolated view of harness-only allocations — the
Rust allocator retains freed memory in its free lists rather than returning it
to the OS, so even after `run_typing` drops all its data structures the
anonymous RSS may not decrease.  The delta is still meaningful because it is
measured within the harness closure: LibAFL's per-iteration work (input
selection, mutation, corpus updates, feedback evaluation) runs *outside* the
closure, so its allocations do not appear in the delta window.  What the metric
captures is: BCS deserialization + `run_typing` allocations + any allocator
free-list growth caused by those calls.  Long campaigns can still drift, but
orders of magnitude more slowly than with `VmRSS`.

Any input whose `RssAnon` delta exceeds `RSS_DELTA_LIMIT_BYTES` is treated as a
crash and saved to `./crashes/`.

The threshold is set empirically: `gen_corpus` runs each seed through the real
pipeline, reports the delta per file, and suggests **5× the worst-case observed
value**.  The seeds are already hand-crafted extremes, so a legitimate fuzz
mutation is unlikely to allocate more than a few multiples of the worst seed;
5× leaves headroom without being so generous that anomalous inputs go
undetected.  As of the current seed set the worst case is
`04_make_move_vec_fan_out_255` at ~12.3 MiB, giving a threshold of **62 MiB**.

This is a starting-point estimate.  After a warm-up run of ~10 minutes,
re-calibrate by plotting the actual RSS-delta distribution across all inputs
that reached `run_typing` and tighten the threshold to the 99.9th percentile
plus one multiplier step.
