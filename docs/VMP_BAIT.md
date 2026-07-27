# VMProtect Bait — Real-Sample Test Harness

`examples/vmp_bait.rs` is a small Windows PE with distinctive
algorithmic hot-loops. Pack it with VMProtect (Free or Trial edition
works), drop the resulting `.exe` into `tests/fixtures/vmpNN/`, and
run `cargo test --features real-samples` to feed the tool a real
VMP-protected binary end-to-end.

This closes the "blocked on samples" gap for our own regression
harness. See `AUDIT_REPORT.md` §5 and `RESEARCH_GAPS.md` §7 item #9.

---

## Step 1 — Build the bait binary for Windows

### On Windows (host build)

```bat
rustup target add x86_64-pc-windows-msvc
cargo build --release --example vmp_bait --target x86_64-pc-windows-msvc
```

Output: `target\x86_64-pc-windows-msvc\release\examples\vmp_bait.exe`

### On Linux (cross-compile — needs `mingw-w64`)

```bash
sudo apt install mingw-w64                          # Debian/Ubuntu
rustup target add x86_64-pc-windows-gnu
cargo build --release --example vmp_bait --target x86_64-pc-windows-gnu
```

Output: `target/x86_64-pc-windows-gnu/release/examples/vmp_bait.exe`

### Smoke-test the unprotected binary

Run it and record the output — you'll compare against the protected
version later to confirm VMProtect didn't corrupt behaviour:

```
> vmp_bait.exe 30
fib(30) = 832040
crc32("Hello, VMProtect!") = 0x23C36A7F
sorted = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
reversed = tcetorPMV
xor_chain(30 rounds) = 0x...(deterministic, will match the protected build)
```

---

## Step 2 — Pack with VMProtect

You need VMProtect (Ultimate or Trial). The free / evaluation version
supports enough features for this workflow.

### GUI workflow (VMProtect 3.x)

1. Open `vmp_bait.exe` in VMProtect.
2. In the **Functions** pane, click **Add Function** and add each of
   the five bait symbols exposed by `#[no_mangle] pub extern "C" fn`:
    - `bait_fibonacci`
    - `bait_crc32`
    - `bait_bubble_sort`
    - `bait_reverse_bytes`
    - `bait_xor_chain`
   VMProtect will find them via the PE export table.
3. For each added function, set **Compilation Type** to
   **Virtualization** (not "Mutation" — that produces a different
   pattern we don't currently target).
4. **Options** tab: leave most defaults, but confirm:
    - "Pack the output file" — **ON** (produces the `.vmp0`/`.vmp1`
      sections our version detector keys on).
    - "Import protection" — **ON** (gives our future
      import-restoration work something to analyse).
    - "Anti-debug" — your choice; ON produces bodies with `Rdtsc` /
      `Cpuid` handler matches; OFF keeps the output slimmer.
    - Compression: **OFF** for the first sample (easier to reason
      about); ON later for a stress test.
5. **Compile**.
6. Save the resulting protected binary as:
    - `tests/fixtures/vmp30/bait_vmp30_msvc.exe` (if VMProtect 3.0-3.4)
    - `tests/fixtures/vmp35/bait_vmp35_msvc.exe` (if VMProtect 3.5.x)
    - `tests/fixtures/vmp36/bait_vmp36_msvc.exe` (if VMProtect 3.6+)
   Naming convention lets the harness route each file to the correct
   version-expectation bucket in `tests/samples.rs`.

### Sanity-check the protected binary

```
> bait_vmp36_msvc.exe 30
fib(30) = 832040
crc32("Hello, VMProtect!") = 0x23C36A7F
sorted = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
reversed = tcetorPMV
xor_chain(30 rounds) = 0x...
```

Every line must match the unprotected output byte-for-byte. If any
differ, VMProtect itself mis-virtualised something — not a
`vmp_devirt` bug. File a VMProtect issue and pick a slightly
different bait (adjust `bait_xor_chain`'s rotate amount or the
sort's compare op) until the round-trip is clean.

---

## Step 3 — Run through `vmp_devirt`

Once the protected `.exe` is in `tests/fixtures/vmpNN/`:

```bash
cargo test --features real-samples validate_real_samples -- --nocapture
```

The harness in `tests/samples.rs` iterates every `.exe` in the
`vmp*/` subdirectories and asserts:

- **family** = `VmProtect` (from `ProtectorDetector`)
- **version** = the subdirectory bucket (from `VersionDetector`)
- **dispatch table VA** is located (from `DispatchTableLocator`)
- **at least one handler classification** succeeded
- **register roles** report at least VSP (from `register_roles::analyse_handlers`)

A one-line-per-sample summary prints to stderr for aggregate hit
rates. Failures name the file + which field diverged from
expectation.

Cross-run with the human-readable CLI to see full analysis on any
one sample:

```bash
./target/release/vmp_devirt.exe tests/fixtures/vmp36/bait_vmp36_msvc.exe \
    --export-analysis /tmp/bait_analysis.json --verbose
```

The `analysis.json` schema is documented in
`src/lib.rs::AnalysisReport` — pretty-print it with `jq` or diff it
against another sample to see what the tool inferred.

---

## Step 4 — Interpret the output (what to look for)

### Family + version detection

Should say `VMProtect` at confidence >= 70. If it says `UnknownProtector`
or a compressor family instead, VMProtect's "Pack the output file"
option was probably off — enable it and re-pack. Sub-version should
land in the 3.x bucket; specific 3.0/3.5/3.6 discrimination depends
on which VMProtect release was used.

### Handler classifications

Look at the per-family counts in the `handler_semantic` field of the
analysis JSON. Each of the five bait functions should contribute
distinct shapes — see the "WHY these functions" section at the top
of `examples/vmp_bait.rs`.

If a handler comes back as `Unknown` or as the unstructured
`handler_type: "MOV_REG_REG"` fallback but with `vmp_semantic: null`,
the semantic matcher missed a shape that a real VMP handler uses.
File a `vmp_devirt` issue with the handler's byte body (grab it from
the exported opcodes JSON) — that's exactly the ground truth we need
to extend `handler_semantic_ext.rs`.

### Register roles

VMProtect 3.x commonly uses `r14`/`r15`/`rbx`/`rdi` as VSP/VIP/VKEY
in some combination. The values will differ per-build (VMProtect
randomises them at protection time), but WITHIN a single sample
every handler should agree. If `vsp_consistency` drops below 0.6
the tool logs a warning — that's Q's cross-handler gate saying the
sample doesn't have a stable convention, which is either a
mis-decoded handler or a genuinely unusual VMP build.

### Semantic coverage percent

Roughly, this is the fraction of the 256 dispatch entries whose
handler body matched at least one `VmpSemantic` variant. A clean
VMProtect 3.x hello-world binary typically lands in the 40-70% range
(many entries share handler VAs — merged handlers — which we don't
distinguish yet). If it's below 20%, `has_xor_reg_imm` or another
core primitive is missing a common opcode shape — file with a body
example.

---

## Deliberate variations to try later

Once the baseline bait sample works, useful variations for stress
tests:

- **VMProtect Ultimate features not in Free** — `import protection`
  full mode, `Watermark`, `License` module. Each adds distinct
  runtime code we'd want the detector to recognise.
- **Different Compilation Types** — Mutation only, Mutation +
  Virtualization, Ultra. Compare classifier output between them.
- **32-bit target** — rebuild the bait with
  `--target i686-pc-windows-msvc`, pack, drop into
  `tests/fixtures/vmp*/bait_vmp*_msvc32.exe`. Exercises the x86
  branch of `handler_semantic_primitives` + `register_roles` that
  the synthetic-samples harness already covers structurally.
- **A trivially-different bait** (change constants, rename functions)
  to confirm the tool's output is stable under per-build noise.

---

## Why THIS bait and not something bigger

Five small functions with distinctive shapes give VMProtect enough
to virtualise WITHOUT swamping the tool with hundreds of virtualised
functions to reason about. A whole real application would be more
representative but would also make regression triage impossible —
"one of 400 handlers changed classification, which one and why?"

Keep the bait small on purpose. Add more functions here (or a
`vmp_bait_v2` example) only when a specific missing coverage area
justifies it.

---

## Not on this list

The bait does NOT try to exercise:
- VMProtect's **merged handler** feature (3.7+) — needs a much bigger
  binary with many small functions VMProtect can share dispatch
  entries across; separate work item.
- **Anti-cheat** or **anti-tamper** SDK usage (Denuvo, EAC, BattlEye
  wrappings around VMP) — those are shipped-with-a-title-only.
- **License** module / hardware-locking — orthogonal to the VM /
  handler pipeline.

If we want to cover any of those, add them as their own bait
programs rather than muddying this one.
