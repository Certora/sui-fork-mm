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

### Re-calibrating the heap threshold (recommended before a full campaign)

The compile-time constant `HEAP_DELTA_LIMIT_BYTES` is a seed-based estimate
(5× the worst corpus seed).  Tighten it against real fuzz traffic in two steps:

**Step 0 — verify the typing pass is being reached**

Before collecting heap deltas it is worth confirming that fuzz inputs are
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

Appends one heap-delta value per iteration to `./heap_deltas.log`.

**Step 2 — apply the derived threshold**

```sh
./translate_and_verify --heap-threshold-from heap_deltas.log
```

Reads `heap_deltas.log`, computes p99.9 × 1.5 (rounded up to the nearest MiB),
prints the derived value to stderr, and uses it as the runtime limit for this
run — no source edit required.  Both flags can be combined to record and apply
simultaneously:

```sh
./translate_and_verify --record-deltas --heap-threshold-from heap_deltas.log
```

After calibration, pass `--heap-threshold-from heap_deltas.log` on every run to
apply the derived threshold automatically.  If you want to bake the value in
permanently, update `HEAP_DELTA_LIMIT_BYTES` in `translate_and_verify.rs` and
rebuild.

Interesting corpus entries accumulate in `./corpus/`.
Crashes and timeouts are saved to `./crashes/`.

---

## Triaging the crashes directory

After a campaign the `./crashes/` directory contains every input that triggered
the objective (crash, timeout, or heap overage) with a unique backtrace hash.
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
file                                                            bytes  stage            heap∆   wall_ms
----------------------------------------------------------------------------------------------------------
e101a7f8bedac268                                             1260376  typing_ok        9.3 MiB        24
9eb9b79caa72d02d                                               1424  decode_fail      0.0 MiB         0
...
```

**Interpreting the columns:**

| Column | Meaning |
|--------|---------|
| `stage` | Where the pipeline stopped: `decode_fail` (BCS parse error), `linkage_fail`, `loading_fail`, or `typing_ok` (reached and completed translate_and_verify) |
| `heap∆` | Net change in jemalloc `stats.allocated` over the iteration — exact bytes allocated and not freed by the harness closure |
| `wall_ms` | Wall-clock time for the iteration |
| `*** PANIC ***` | The input triggered a panic or `invariant_violation!` — a real finding |
| `*** HEAP ***` | `heap∆` exceeded 62 MiB — a potential OOM finding |

**What to look for:**

- Any line with `*** PANIC ***` is a real bug.  Replay that single file to get the full backtrace:
  ```sh
  RUST_BACKTRACE=1 ./replay crashes/<hash>
  ```
- Lines where `stage = decode_fail` or `loading_fail` are almost certainly false positives — the input never reached the target.
- `typing_ok` with low `heap∆` and short `wall_ms` that re-runs cleanly indicates the objective was triggered by baseline drift in a previous campaign that used OS-level RSS metrics. These are not findings.
- High `heap∆` values on `typing_ok` inputs that don't panic are worth investigating: they indicate the typing pass allocates pathologically on certain input shapes even without crashing.

**Prioritisation:**

```sh
# Panics first
./replay crashes/ | grep 'PANIC'

# Then large heap allocation on typing_ok inputs
./replay crashes/ | awk '$3=="typing_ok" {gsub(/MiB/,""); if ($4+0 > 20) print}' | sort -k4 -rn

# Ignore decode_fail and loading_fail entirely
./replay crashes/ | grep -v 'decode_fail\|loading_fail'
```

### Known false-positive pattern: OS-level RSS drift

Earlier versions of the harness measured `VmRSS` or `RssAnon` from
`/proc/self/status`.  Both are OS-level resident-page counts with two
fundamental problems as per-input allocation signals:

- **Page granularity**: RSS only changes in 4 KiB increments. Allocations that
  land in already-resident pages show as zero delta even if the harness
  allocated many megabytes.
- **Free-list masking**: the allocator retains freed pages in its free list
  rather than returning them to the OS immediately. After a large allocation is
  freed the RSS stays elevated, making the *next* iteration's baseline higher
  than expected and its delta appear negative or near-zero.

Over a 22-hour campaign these effects accumulated into hundreds of false-positive
objectives: inputs whose `VmRSS` delta exceeded the threshold during the run
but showed near-zero allocation on replay.

The harness now uses jemalloc `stats.allocated` instead, which measures exact
bytes handed out by the allocator and not yet freed — no page granularity, no
free-list masking, and no shared-memory contamination.

---

## Corpus generator (`gen_corpus`)

`gen_corpus` produces BCS-serialized `ProgrammableTransaction` files that give
the fuzzer structurally valid starting points.  Random bytes almost never
decode as a valid PTB, so without a seed corpus the fuzzer spends nearly all
its time on inputs that are rejected at the BCS layer before any interesting
code is reached.

Each seed is a hand-crafted worst case for a specific code path in the typing
pipeline.  The seeds are grouped into three tiers by what they can exercise.

### Tier 1 — built-in commands only (01–16)

These seeds use only `SplitCoins`, `MergeCoins`, `MakeMoveVec`, and
`TransferObjects`.  They never reference an on-chain package, so they pass
loading entirely and drive the typing pass directly.

| File | Strategy | What it stresses |
|------|----------|-----------------|
| `01_minimal_transfer` | Single `TransferObjects(GasCoin, addr)` | Baseline — fixture initialises correctly, well-formed PTB passes all checks |
| `02_empty_ptb` | Zero inputs, zero commands | Empty-collection handling throughout the pipeline |
| `03_split_merge_chain_512` | 512 alternating `SplitCoins`/`MergeCoins` pairs | `memory_safety`: O(n) `Vec<Delta>` growth in the reference derivation chain |
| `04_make_move_vec_fan_out_255` | One `MakeMoveVec` with 255 identical arguments | O(#args) result-accumulation loop in `translate::Context` |
| `05_deep_result_chain_64` | 64 `MakeMoveVec` commands, each wrapping the previous | `Path::extensions` clone depth |
| `06_deep_type_args_16` | `MoveCall` with a type argument nested 16 levels deep | `metering::typing` type-node counting; `max_type_argument_depth` |
| `07_wide_type_args_16` | `MoveCall` with 16 distinct type arguments | Type-argument width validation and per-argument metering |
| `08_max_pure_multi_use_64` | Single 16 KiB pure input referenced by 64 commands | `IndexSet` bytes-interning growth; pure-input re-evaluation |
| `09_nested_result_crossref_512` | 512-command `NestedResult` chain, each referencing the previous | `NestedResult` index handling; `translate::Context::locations()` |
| `10_transfer_fan_in_255` | 255 `SplitCoins` results into one `TransferObjects` | Many-input memory-safety tracking; argument-count validation |
| `11_split_many_amounts_255` | `SplitCoins(GasCoin, [amt]*255)` | Multi-return result sub-index handling |
| `12_nested_result_fan_in_64` | `SplitCoins` → 64 results → `TransferObjects` via `NestedResult(0,i)` | `NestedResult` sub-index validation across a wide range |
| `13_split_chain_256` | 256-deep chain of `SplitCoins` each consuming the previous | Linear mutable-borrow derivation; `Path::extensions` growth |
| `14_make_vec_primitives` | Three `MakeMoveVec` commands over `Bool`, `U8`, `Address` (32 args each) | Primitive type unification; pure-input interning across expected types |
| `15_merge_split_cycle` | `SplitCoins`→`MergeCoins`→`SplitCoins`→`MergeCoins` on `NestedResult` refs | Borrow-graph path convergence; non-linear derivation chains |
| `16_split_max_width_boundary` | `SplitCoins(GasCoin, [amt]*255)` + `TransferObjects` at indices 0 and 254 | Maximum sub-result index validation; `u16` boundary near 255 |

### Tier 2 — MoveCall into framework packages (17–25)

These seeds call functions in `0x1` (Move stdlib) or `0x2` (Sui framework),
which are present in the fixture store.  They exercise `MoveCall` typing with
real package resolution.

| File | Strategy | What it stresses |
|------|----------|-----------------|
| `17_move_call_no_args` | `0x2::address::length()` — no inputs, no type args | Minimal MoveCall path through loading + typing |
| `18_move_call_pure_primitive` | `0x2::address::from_u256(u256)` — pure input → primitive param | Pure-input → primitive-parameter binding; type inference inside MoveCall |
| `19_move_call_vector_arg` | `0x1::ascii::string(vector<u8>)` — pure bytes → `vector<u8>` param | Pure-input → `vector<u8>` binding; framework struct as result type |
| `20_move_call_generic_type_arg` | `0x1::type_name::get<Coin<SUI>>()` — generic with no value args | Generic type-arg substitution when there are no value arguments to constrain it |
| `21_move_call_reference_arg` | `0x2::hash::keccak256(&vector<u8>)` — pure input by immutable ref | Borrow inference for pure input fed to a `&T` parameter |
| `22_move_call_result_chain_64` | 64 alternating `from_u256`/`to_u256` calls threading results | Result-type propagation across many MoveCalls |
| `23_move_call_make_vec_of_results_64` | 64 `from_u256` calls + `MakeMoveVec<address>([R0..R63])` | MoveCall results fed into a built-in command's argument list |
| `24_make_move_vec_none_infer` | `MakeMoveVec(None, [addr, addr])` — type inferred, not annotated | `MakeMoveVec` element-type inference branch; object-type validation error path |
| `25_make_move_vec_empty_typed` | `MakeMoveVec<u64>([])` — typed but empty | Zero-argument branch of `MakeMoveVec` typing |

### Tier 3 — MoveCall into the synthetic fuzz-fixture package (26–80)

The fuzz-fixture package ([`fuzz_fixture.rs`](fuzz_targets/fuzz_fixture.rs), address
`0xface`) is compiled at harness startup and injected into the in-memory store
alongside the system packages.  It exposes a wide variety of function signatures
and object types so `MoveCall` seeds have a controllable, resolvable target that
covers paths the framework seeds cannot reach:

- **Structs**: `Box` (copy+drop+store), `Pair<T>` (copy+drop), `KeyBox` (key+store),
  `HotPotato` (copy only — non-droppable), `DropOnly` (drop only)
- **Functions**: primitives, vectors, immutable/mutable references, generics with
  single/double/triple ability bounds, struct constructors, multiple-return tuples,
  entry/private visibility variants, object-by-value and object-by-reference variants,
  and `Receiving<T>` parameters

#### 26–32: basic fixture MoveCall (pure inputs only)

| File | Strategy | What it stresses |
|------|----------|-----------------|
| `26_fixture_no_args` | `nothing()` — no arguments, no return | Minimal MoveCall to a user package |
| `27_fixture_take_primitive` | `take_u64(u64) → u64` | Pure input → user-function primitive parameter |
| `28_fixture_struct_roundtrip` | `new_box(u64) → Box`, then `unbox(Box) → u64` | User-defined struct flowing as a MoveCall result into another call |
| `29_fixture_generic_identity` | `identity<u64>(u64) → u64` | Generic substitution with a fixed type argument and a pure input |
| `30_fixture_multi_return` | `two_values() → (u64, bool)`, components consumed via `NestedResult` | `NestedResult` sub-index on a MoveCall multiple-return |
| `31_fixture_make_pair` | `make_pair<u64>(u64, u64) → Pair<u64>` — copyable pure input reused twice | Generic struct constructor with ability bounds; pure-input reuse |
| `32_fixture_reference_arg` | `use_imm_ref(&u64) → u64` | Borrow inference for a pure input passed to a user function's `&T` |

#### 33–43: object-input seeds

These seeds use `CallArg::Object` — owned, shared, immutable, and `Receiving` objects
from the fixture store.  They drive the object-input loading and borrow-tracking paths
that pure-input seeds never reach.

| File | Strategy | What it stresses |
|------|----------|-----------------|
| `33_split_owned_coin` | `SplitCoins` on an owned `Coin` object input | `ImmOrOwnedObject` loading; owned-coin memory-safety tracking |
| `34_merge_two_owned_coins` | `MergeCoins` across two distinct owned coin inputs | Multiple object inputs; MergeCoins fan-in on non-gas coins |
| `35_transfer_owned_coin` | `TransferObjects` consuming an owned coin | Object-input by-value transfer path |
| `36_split_shared_coin` | `SplitCoins` on a `SharedObject{mutable}` coin | Shared-object loading; mutable shared-object borrow tracking |
| `37_move_call_immutable_coin_ref` | `coin::value(&Coin<SUI>)` with an immutable coin | `ImmOrOwnedObject` passed as `&T` to a framework function |
| `38_move_call_owned_coin_ref` | `coin::value(&Coin<SUI>)` with an owned coin | Owned-object borrow as immutable ref |
| `39_transfer_key_box_object` | `transfer::transfer(KeyBox, addr)` — transfers a `key+store` object | `key` object by value to a transfer call |
| `40_move_call_key_box_by_value` | `take_key_box(KeyBox) → u64` | User-function consuming a `key+store` object by value |
| `41_move_call_key_box_ref` | `key_box_value(&KeyBox) → u64` | Owned object passed as immutable ref to a user function |
| `42_receive_sui_coin_to_parent` | `receive_sui_coin(&mut KeyBox, Receiving<Coin<SUI>>)` | `Receiving<T>` argument typing; mutable parent object |
| `43_receive_key_box_to_parent` | `receive_key_box(&mut KeyBox, Receiving<KeyBox>)` | `Receiving<T>` with a user-defined `key` type |

#### 44–71: error-path seeds

Seeds that are expected to return `Err(…)` from the typing/loading pass, targeting
specific validation branches that well-formed inputs never exercise.

| File | Error exercised |
|------|----------------|
| `44_err_fixture_wrong_arity` | Wrong value-argument count to a fixture function |
| `45_err_fixture_wrong_primitive` | Wrong primitive type (`u8` where `u64` expected) |
| `46_err_input_index_oob` | `Input(99)` on a single-input PTB |
| `47_err_coin_value_wrong_type_arg` | `coin::value` called with `Coin<SUI>` as type arg instead of `SUI` |
| `48_err_nested_result_secondary_oob` | `NestedResult(0, 3)` when command 0 produced only 1 sub-result |
| `49_err_merge_invalid_result_arity` | `MergeCoins` returns nothing; referencing `Result(0)` |
| `50_err_transfer_immutable_by_value` | Transferring an `Immutable` coin object by value |
| `51_err_option_inner_type_mismatch` | `option::some<u64>` with a `u8` BCS input |
| `52_err_mut_ref_on_coin_object` | `use_mut_ref(&mut u64)` fed an owned coin object |
| `53_err_make_move_vec_elem_type_mismatch` | `MakeMoveVec<u64>` with a `u8` element |
| `54_err_object_input_reuse_after_move` | Same `KeyBox` consumed twice by value |
| `55_err_result_index_oob` | `Result(99)` on an empty command list |
| `56_err_transfer_wrong_recipient_type` | `TransferObjects` with a non-address recipient |
| `57_err_split_immutable_coin` | `SplitCoins` on an immutable coin |
| `58_err_fixture_struct_type_mismatch` | Struct type from one function fed to a parameter expecting a different struct |
| `59_err_from_u256_truncated_bytes` | `from_u256` with fewer than 32 bytes |
| `60_err_private_non_entry` | Calling a `fun` (non-public, non-entry) from a PTB |
| `61_fixture_private_entry_ok` | Calling an `entry fun` from a PTB — valid |
| `62_err_hot_potato_private_entry` | Hot-potato passed to a `fun` (not `entry`) — rejected |
| `63_err_unused_hot_potato` | `make_hot_potato()` with no consumer — non-droppable result leaked |
| `64_err_unused_multi_return_hot_potato` | `two_hot_potatoes()` with no consumers |
| `65_fixture_mut_ref_pure_u64` | `use_mut_ref(&mut u64)` with a pure input — valid borrow |
| `66_move_call_coin_split_consume` | `coin::split` on an owned coin, result transferred |
| `67_err_unused_coin_split_result` | `coin::split` result left unconsumed (non-droppable `Coin`) |
| `68_move_call_coin_join` | `coin::join` merging two coins |
| `69_move_call_public_freeze_key_box` | `transfer::freeze_object(KeyBox)` — permanently freezes |
| `70_move_call_public_share_key_box` | `transfer::share_object(KeyBox)` — makes shared |
| `71_err_transfer_private_generics` | `transfer::transfer` with a type that has private generics |

#### 72–80: ability-diverse generics and error paths

Seeds targeting the generic-instantiation and ability-constraint branches added to
the fixture in a second pass, after coverage analysis showed those paths were unreached.

| File | Strategy | What it stresses |
|------|----------|-----------------|
| `72_fixture_pair_transform` | `pair_transform<u64, bool>(u64, bool) → (bool, u64)` | 2-type-param instantiation with independent `copy+drop` bounds on each |
| `73_fixture_three_generics` | `three_generics<u64, bool, address>(u64, bool, addr) → u64` | 3-type-param instantiation; drop-only constraints |
| `74_fixture_three_vals` | `three_vals() → (u64, bool, address)`, sub-results consumed via `NestedResult(0, 0..2)` | 3-element tuple return; all three `NestedResult` sub-indices |
| `75_fixture_store_id_valid` | `store_id<Box>(new_box(v)) → Box` — `Box` satisfies the `store` constraint | `store`-bound generic with a valid type arg |
| `76_fixture_copy_store_id_valid` | `copy_store_id<Box>(new_box(v)) → Box` — `Box` satisfies `copy + store` | `copy + store`-bound generic instantiation path |
| `77_fixture_make_drop_only` | `make_drop_only(v) → DropOnly` — result has only `drop` | Drop-only result type; no `copy` or `store` |
| `78_err_store_id_ability_violation` | `store_id<DropOnly>` — `DropOnly` has `drop` only, not `store` | Bytecode verifier ability-constraint failure in loading pass |
| `79_err_ignore_ability_violation` | `ignore<KeyBox>` — `KeyBox` has `key+store`, not `drop` | Same; `drop`-bound violation |
| `80_err_three_vals_spurious_type_args` | `three_vals<u64, bool, address>()` — function has 0 type params | Type-argument count mismatch (too many) in loading pass |

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
fuzzing.  The 4 GiB ceiling is well above any legitimate PTB; the heap delta
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

### Heap allocation guard

A heap delta guard reads `jemalloc`'s `stats.allocated` counter before and
after each harness call.  Any input whose net allocation exceeds
`HEAP_DELTA_LIMIT_BYTES` is treated as a crash and saved to `./crashes/`.

`stats.allocated` is the number of bytes currently handed out by jemalloc and
not yet freed, summed across **all arenas and all threads**.  It is
fundamentally different from OS-level RSS metrics:

- No page-granularity noise (RSS only moves in 4 KiB increments; jemalloc
  reports exact bytes).
- No free-list masking (RSS stays high after free because the OS hasn't
  reclaimed the pages; `stats.allocated` drops immediately when memory is
  freed).
- No shared-memory or file-backed page contamination.
- Covers all threads, not just the main arena (`mallinfo2` only covers the
  main arena, missing per-thread arenas created under lock contention).

`epoch::advance()` is called before each read to flush jemalloc's per-thread
caches into the global counters; without this the read may be stale by up to
one cache flush interval.

The threshold is set empirically: `gen_corpus` runs each seed through the real
pipeline, reports the delta per file, and suggests **5× the worst-case observed
value**.  As of the current seed set the worst case is
`04_make_move_vec_fan_out_255` at ~12.3 MiB, giving a threshold of **62 MiB**.
Re-calibrate with `--heap-threshold-from` after a ~10-minute warm-up run.
