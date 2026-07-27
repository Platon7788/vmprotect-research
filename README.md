# VMP Devirtualizer

Rust CLI + library for analyzing VMProtect-obfuscated binaries. Loads PE binaries, locates the VM dispatch table, extracts and classifies handlers, and decodes bytecode into a JSON/text trace.

> **Status:** research prototype. Reliable path is **VMP 3.0-3.6** (with a valid dispatch-table RVA). VMP 1.x / 2.x detection is heuristic-only; VMP 3.7+ (merged handlers) is not supported. See [Known Limitations](#known-limitations) and [`AUDIT_REPORT.md`](./AUDIT_REPORT.md).

---

## Features

- PE loader (Windows + Linux ELF via `goblin`), with dual-bitness support (x86 PE32 + x86-64 PE32+)
- Protector-family detector — a class-level "some protector" gate (entropy / W+X / stripped-IAT / EP-outside-`.text`) plus byte-table matchers for 10 VM-based vendor families (VMProtect, Themida/WinLicense, Code Virtualizer, Enigma, Obsidium, Armadillo, ASPack, Denuvo — detected and deliberately refused) and 5 compressor families (UPX/MPRESS/Petite/PECompact/Upack), short-circuited before the VMP-specific pipeline runs
- VM version heuristics (VMProtect only) — scored rule cascade over entry-stub bytes, `.vmp0`/`.vmp1` section layout, and auxiliary markers, returning a version + 0-100 confidence, plus VMP 3.x sub-version hints
- Dispatch-table locator (256-entry pointer table scan + optional `--dispatch-rva` hint), plus a structural three-instruction dispatcher fingerprint scan for renamed-section VMP (BattlEye BEDaisy, EAC)
- Handler classifier (x86 / x86-64 first-byte + REX-prefix patterns, bitness-gated)
- Junk-code stripper — peephole passes (Groups A-G: dead-store elimination, constant folding, backward liveness) run to fixed-point before semantic matching, so mutation-envelope junk between real instructions no longer defeats fingerprints
- VMP-semantic handler matcher (`VmpSemantic`) covering the full **35/35**-category taxonomy layered on top of the x86-level classifier, with per-classification confidence scoring
- Register-role canonicaliser — votes which GPR plays VIP / VSP / VKEY across all handler bodies in a binary, with a cross-handler consistency gate
- Optional Unicorn CPU-emulation extraction via Python `unicorn` subprocess
- Per-VMP-version operand decryption (`CryptoScheme`: `Vmp2Rolling` / `Vmp3PerHandler`), wired into bytecode operand decoding
- ALU chain (NOR / NAND) → arithmetic op mapping, wired into the devirtualization pipeline
- JSON export for opcode table, handler classifications, and a unified `--export-analysis` report (family + version + confidence + dispatch + register roles + handler classifications + crypto scheme + coverage %)
- Real-sample (`--features real-samples`) and synthetic-sample (`--features synthetic-samples`) validation harnesses

---

## Build

Requires Rust 1.85+ (tested on 1.97.1). No external native deps for the core library — `goblin` is pure Rust.

```bash
cargo build --release
```

Binary: `target/release/vmp_devirt` (Linux/macOS) or `target\release\vmp_devirt.exe` (Windows).

### Optional: Unicorn-based dispatch extraction

The primary dispatch-extraction path shells out to a Python script that uses the `unicorn` engine. This is **optional** — if the script is not found, the code falls back to pure-Rust static XOR-key analysis.

To enable:

```bash
pip install unicorn
# Place unicorn_extractor.py under ./scripts/ OR set the env var:
export VMP_UNICORN_EXTRACTOR=/path/to/unicorn_extractor.py
```

The script is **not included in this repository** yet — see `AUDIT_REPORT.md` §Q15 (planned migration to the `unicorn-engine` Rust crate).

Lookup order for the script:
1. `$VMP_UNICORN_EXTRACTOR` env var
2. `$CARGO_MANIFEST_DIR/scripts/unicorn_extractor.py`
3. `./scripts/unicorn_extractor.py` (CWD)

Extraction output is written to `std::env::temp_dir()/vmp_devirt_dispatch_entries.json`.

---

## Usage

```bash
# Analyze binary (auto-detect version, locate dispatch table, classify handlers)
./target/release/vmp_devirt <binary>

# Export handler classifications as JSON
./target/release/vmp_devirt <binary> --export-handlers handlers.json

# Export opcode table
./target/release/vmp_devirt <binary> --export-opcodes opcodes.json

# Devirtualize a range starting at a VIP address (hex, with or without 0x)
# Defaults to the PE entry point if --vip is omitted.
./target/release/vmp_devirt <binary> --vip 0x140001000 --format json

# Override auto-detected version for research (skips the non-VMP exit gate)
./target/release/vmp_devirt <binary> --force-version vmp35

# Export the unified analysis report as JSON: family + version + confidence +
# dispatch table + register roles + handler classifications + crypto scheme +
# coverage percentage, all in one file.
./target/release/vmp_devirt <binary> --export-analysis analysis.json
```

Full CLI reference: `vmp_devirt --help`.

**Exit codes:** `0` on success, `1` on generic error, `2` (`EXIT_NOT_VMP`) when the binary does not look VMP-protected (detector returned `Unknown`/low confidence and no dispatch table was found) — pass `--force-version` and/or `--dispatch-rva` to override.

---

## Architecture

```
Input Binary (PE / ELF)
        │
        ▼
 PE Loader (src/pe_loader.rs)                      goblin
        │
        ▼
 Protector Detector (src/protector.rs)             class-level gate + 10 vendor +
        │                                          5 compressor byte-table matchers
        ▼  (only proceeds past this point if family == VmProtect)
 Version Detector (src/version.rs)                 .vmp0/.vmp1 heuristics + sub-hints
        │
        ▼
 Dispatch Table Locator (src/dispatch_table.rs)    known-RVA hint + fallback scan +
        │                                          structural dispatcher fingerprint
        ├──► Dispatch Extractor (Python bridge)    src/dispatch_extractor_py.rs
        └──► XOR Key Analyzer (static)              src/xor_key_analyzer.rs
        │
        ▼
 Handler Classifier (src/handler_classifier.rs)    x86-64 pattern match
        │
        ▼
 Junk Stripper (src/junk_stripper*.rs)             peephole Groups A-G, fixed-point
        │
        ▼
 Semantic Classifier (src/handler_semantic*.rs)    VmpSemantic, 35/35 taxonomy
        │
        ▼
 Register Role Canonicaliser (src/register_roles*.rs)  VIP/VSP/VKEY vote + consistency
        │
        ▼
 Bytecode Decoder (src/bytecode.rs)                per-handler operand decode
        │
        ├──► Operand Decryption                    src/decrypt.rs (CryptoScheme per version)
        └──► ALU Reconstruction                    src/alu.rs (NOR/NAND chains)
        │
        ▼
 Output (JSON / text / --export-analysis)          src/bin/cli.rs

 Synthetic-sample generator (src/synthetic_sample*.rs) — feeds the same pipeline
 with VMP-shaped fixtures for structural end-to-end validation without real
 binaries (gated behind `--features synthetic-samples`, see tests/synthetic.rs).
```

---

## Module map

| Module(s) | Purpose |
|--------|---------|
| `src/lib.rs` | Public API — `VmpDevirtualizer` facade, `AnalysisReport` (unified export shape) |
| `src/protector.rs`, `protector_matchers.rs`, `protector_signals.rs` (+ `protector_tests.rs`, `protector_signals_tests.rs`) | Protector-family detection: class-level "some protector" gate + 10 vendor byte-table matchers + structural VMP dispatcher fingerprint |
| `src/version.rs`, `version_matchers.rs` (+ `version_tests.rs`) | VMP version discrimination (scored rule cascade) + entry-stub/section-layout pattern matchers + sub-version hints |
| `src/dispatch_table.rs`, `dispatch_extractor_py.rs`, `xor_key_analyzer.rs` | Dispatch-table extraction: known-RVA hint + fallback pointer scan, Python-`unicorn` bridge, static XOR-key analysis |
| `src/handler_classifier.rs`, `handler_semantic.rs`, `handler_semantic_ext.rs`, `handler_semantic_primitives.rs` (+ `handler_semantic_tests.rs`, `handler_semantic_ext_tests.rs`, `handler_semantic_o_tests.rs`) | Handler classification: x86-level byte/REX matching, then `VmpSemantic` (35/35-category taxonomy) with wire-through of the junk stripper and per-classification confidence scoring |
| `src/junk_stripper.rs`, `junk_stripper_length.rs`, `junk_stripper_effects.rs`, `junk_stripper_effects_helpers.rs`, `junk_stripper_folds.rs` (+ `junk_stripper_tests.rs`, `junk_stripper_folds_tests.rs`) | Peephole passes (Groups A-G: dead-store elimination, constant folding, backward liveness) run to fixed-point before semantic matching |
| `src/register_roles.rs`, `register_roles_consistency.rs` (+ `register_roles_tests.rs`) | VIP/VSP/VKEY register-role voting across handler bodies, plus a cross-handler consistency gate |
| `src/bytecode.rs`, `decrypt.rs` (+ `decrypt_tests.rs`), `alu.rs` | Bytecode operand decode, per-VMP-version `CryptoScheme` dispatch, NOR/NAND ALU-chain reconstruction |
| `src/pe_loader.rs`, `pe_loader_test_util.rs` | PE binary loading, VA↔offset mapping, shared test fixture builder |
| `src/synthetic_sample.rs`, `synthetic_sample_handlers.rs` | Feature-gated (`synthetic-samples`) VMP-shaped PE emitter for structural end-to-end pipeline validation |
| `src/opcode_table.rs` | Opcode ↔ handler mapping (serialize/deserialize) |
| `src/bin/cli.rs` | CLI, including `--export-analysis` (unified JSON report) and `EXIT_UNSUPPORTED_FAMILY` (exit code 3) for detected-but-unsupported vendors |

14,102 lines of Rust across 39 files (`wc -l src/*.rs src/bin/*.rs`, 2026-07-27).

---

## Test status

`cargo test --all-targets` — 307 lib unit tests + 1 bin test + 7 integration tests = **315 total**, all green (up from 111 before the research-gap remediation pass, up from 66, up from 16 originally). `cargo test --features synthetic-samples --all-targets` — **322 total** (310 lib + 1 bin + 7 integration + 4 synthetic e2e). `cargo clippy --all-targets --all-features` — 0 warnings. This is a local-only research project — there is no CI. All four gates (`build`, `test`, `clippy --all-targets -- -D warnings`, `fmt --check`) must be run locally before commit. Tool configs (`rustfmt.toml`, `clippy.toml`, `deny.toml`) stay checked in for consistent local runs.

Integration tests (`tests/cli.rs`, via `assert_cmd`) exercise the compiled CLI binary against in-memory-fixture-backed PE files: default `--vip` resolution, the non-VMP exit-code gate, `--force-version` override (including its rejection of unknown values), protector-family log line, `--export-analysis` JSON validity, and short-flag disambiguation as a regression guard.

Real end-to-end validation against VMP-protected sample binaries has **not been re-run since the current audit**. Earlier internal reports (`docs/VALIDATION_REPORT.md`) claim 22/22 samples pass, but they predate the audit. Take those numbers as historical, not current. VMP 1.x / 2.x detection is no longer a stub (see below), but no live x86 VMP-protected binary has been analyzed end-to-end with the current code.

---

## Real-sample validation

`cargo test` (no flags) never touches real VMP-protected binaries — every
assertion above runs against synthetic in-memory PE fixtures. Actually
validating the family/version detector and dispatch-table locator against
real VMProtect output requires a `--features real-samples` opt-in:

```bash
cargo test --features real-samples
```

This compiles and runs `tests/samples.rs`, which walks `tests/fixtures/vmp1/`,
`vmp2/`, `vmp30/`, `vmp35/`, `vmp36/`, and `non_vmp/` for `.exe` files, runs
`vmp_devirt` against each, and checks the reported protector family, VMP
version, and dispatch-table location against what that subdirectory is
supposed to contain. An empty (or entirely absent) `tests/fixtures/` tree is
not a failure — the harness logs a skip line per empty group and a one-line
summary, then passes cleanly, because the corpus is user-provided and this
project runs no CI (see `tests/fixtures/README.md` for sourcing, naming, and
legal notes — **do not commit third-party VMP-protected binaries**).

This makes the previously-aspirational "validate against real VMP-3
binaries" line item (`RESEARCH_GAPS.md` §7 item #9) checkable: the harness
exists now, and turns from "0 tests, 0 samples" into real pass/fail feedback
the moment you drop binaries into `tests/fixtures/`.

### Synthetic-sample validation (structural, no real binaries needed)

A second harness, gated behind `--features synthetic-samples`, does not wait
for real VMP binaries at all:

```bash
cargo test --features synthetic-samples
```

This compiles `src/synthetic_sample.rs` (a VMP-shaped PE generator — correct
section layout, entry stub, structural dispatcher fingerprint, 256-entry
dispatch table, 30 handler shells covering 11 semantic categories) and runs
`tests/synthetic.rs`: 4 end-to-end tests that hand each generated fixture to
the compiled CLI via `assert_cmd`, parse the `--export-analysis` JSON, and
assert that family detection, version detection, dispatch-table location,
register-role voting, and handler semantic classification all agree with
what the generator baked in and with each other. Where the real-sample
harness above validates against ground truth that doesn't exist yet in this
repo, the synthetic harness validates the pipeline's internal consistency
today — it cannot catch a systematic misunderstanding of real VMP's byte
shapes, but it does catch regressions in how the stages agree with each
other.

---

## Development

```bash
cargo build                              # debug build
cargo test --all-targets                 # 315 tests (307 lib + 1 bin + 7 integration)
cargo test --features synthetic-samples --all-targets  # 322 tests (adds 3 lib + 4 e2e)
cargo clippy --all-targets --all-features -- -D warnings  # must be clean
cargo fmt --check                        # style is enforced project-wide (rustfmt.toml)
```

No CI. All four gates above are the developer's responsibility to run locally
before every commit. Supply-chain audits are also local: `cargo audit` and
`cargo deny check` (config: `deny.toml`) — run them when changing
dependencies.

---

## Known Limitations

1. **VMP 3.7+ (merged handlers) is not supported.** The classifier assumes one opcode → one handler entry, which breaks on 3.7+. The register-role voter (`src/register_roles.rs`) is a necessary foundation for a future cross-handler DFA that could split merged handlers back apart, but that DFA does not exist yet. See `docs/FUTURE_WORK.md`.
2. **The VMP-semantic handler classifier is comprehensive at the taxonomy level (35/35 categories in `VmpSemantic`, `src/handler_semantic.rs`, populated by `classify()` with per-category confidence scoring) but crypto/operand-value correctness is unvalidated without real samples.** The matcher shapes are structural byte-pattern checks (`is_*_shape` functions), not full semantic verification — they establish "this looks like an ADD handler," not "this handler computes the correct ADD." The 8+ confirmed non-issues found during the T/U/V audit (e.g. `CryptoScheme` invertibility, `Popreg`/`Popstk` disjointness) demonstrate structural self-consistency; validating that decrypted operand *values* match real VMP output is the Days 6-7 work in `AUDIT_REPORT.md`, blocked on real sample availability. The legacy x86-instruction-level `handler_type` string remains available as a fallback label for consumers that don't yet read `vmp_semantic`.
3. **ALU chains ARE reconstructed** on the last instruction of a NOR/NAND run (`alu::reconstruct_alu_chains`, wired into `VmpDevirtualizer::devirtualize_range`), and `decompose_chain` returns symbolic stack-slot names (`"vsp+0"`, `"vsp+8"`) rather than the old `"stack_val_1"`/`"stack_val_2"` placeholders. What remains open: the chain-length pattern table in `src/alu.rs` is still hardcoded (4-instruction runs → `Add`, 2-instruction runs → `And`, etc.) and unvalidated against real VMP samples, and slot naming is hardcoded to the x64 stack convention. Tracked as Q3 / Days 6-7 in `AUDIT_REPORT.md`.
4. **Python subprocess dependency** for the Unicorn extraction path. Not required — the code falls back to static XOR-key analysis — but the `unicorn_extractor.py` script itself is not bundled in this repository yet (see `AUDIT_REPORT.md` §Q15).
5. **Dual-bitness support (x86 PE32 + x86-64 PE32+) is new and only validated structurally.** `Bitness`-aware handling exists in the XOR key analyzer and handler classifier (entry size, XOR-immediate encoding, REX-prefix gating), and is covered by in-memory unit tests for both bitnesses, but has not been exercised end-to-end against a real 32-bit VMP-protected binary.

---

## Documentation

- [`AUDIT_REPORT.md`](./AUDIT_REPORT.md) — **current** audit, applied fixes, and prioritized roadmap
- [`docs/VALIDATION_REPORT.md`](./docs/VALIDATION_REPORT.md) — historical validation (pre-audit)
- [`docs/IMPLEMENTATION_COMPLETE.md`](./docs/IMPLEMENTATION_COMPLETE.md) — implementation status snapshot
- [`docs/UNICORN_IMPLEMENTATION_REPORT.md`](./docs/UNICORN_IMPLEMENTATION_REPORT.md) — Python-bridge design
- [`docs/FUTURE_WORK.md`](./docs/FUTURE_WORK.md) — VMP 3.7+ analysis notes

---

## Source references

Handler structure, dispatch mechanism, ValueCryptor chain, and ALU patterns are informed by public VMProtect 3.5.1 source-leak analysis. This project does not redistribute VMProtect source.

---

## License

MIT — research / educational use only. Do not use this tool to bypass software protection on programs you do not own or have explicit authorization to analyze.
