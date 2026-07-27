# VMP Devirtualizer

Rust CLI + library for analyzing VMProtect-obfuscated binaries. Loads PE binaries, locates the VM dispatch table, extracts and classifies handlers, and decodes bytecode into a JSON/text trace.

> **Status:** research prototype. Reliable path is **VMP 3.0-3.6** (with a valid dispatch-table RVA). VMP 1.x / 2.x detection is heuristic-only; VMP 3.7+ (merged handlers) is not supported. See [Known Limitations](#known-limitations) and [`AUDIT_REPORT.md`](./AUDIT_REPORT.md).

---

## Features

- PE loader (Windows + Linux ELF via `goblin`), with dual-bitness support (x86 PE32 + x86-64 PE32+)
- VM version heuristics — scored rule cascade over entry-stub bytes, `.vmp0`/`.vmp1` section layout, and auxiliary markers, returning a version + 0-100 confidence
- Dispatch-table locator (256-entry pointer table scan + optional `--dispatch-rva` hint)
- Handler classifier (x86 / x86-64 first-byte + REX-prefix patterns, bitness-gated)
- VMP-semantic handler matcher (`VmpSemantic`, 8 of ~35 categories recognized) layered on top of the x86-level classifier
- Optional Unicorn CPU-emulation extraction via Python `unicorn` subprocess
- ValueCryptor / CRC operand decryption, wired into bytecode operand decoding
- ALU chain (NOR / NAND) → arithmetic op mapping, wired into the devirtualization pipeline
- JSON export for opcode table and handler classifications

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
 Version Detector (src/version.rs)                 .vmp0/.vmp1 heuristics
        │
        ▼
 Dispatch Table Locator (src/dispatch_table.rs)    known-RVA hint + fallback scan
        │
        ├──► Dispatch Extractor (Python bridge)    src/dispatch_extractor_py.rs
        └──► XOR Key Analyzer (static)             src/xor_key_analyzer.rs
        │
        ▼
 Handler Classifier (src/handler_classifier.rs)    x86-64 pattern match
        │
        ▼
 Bytecode Decoder (src/bytecode.rs)                per-handler operand decode
        │
        ├──► Operand Decryption                    src/decrypt.rs (CRC / ValueCryptor)
        └──► ALU Reconstruction                    src/alu.rs (NOR/NAND chains)
        │
        ▼
 Output (JSON / text)                              src/bin/cli.rs
```

---

## Module map

| Module | Purpose |
|--------|---------|
| `src/lib.rs` | Public API — `VmpDevirtualizer` façade |
| `src/pe_loader.rs` | PE binary loading + VA↔offset mapping |
| `src/version.rs` | VMP-version heuristics (scored rule cascade) |
| `src/version_matchers.rs` | Entry-stub / section-layout pattern matchers used by `version.rs` (private) |
| `src/dispatch_table.rs` | Dispatch-table locator + validator |
| `src/xor_key_analyzer.rs` | Static XOR-key extraction (256 entries) |
| `src/dispatch_extractor_py.rs` | Python-`unicorn` subprocess bridge |
| `src/handler_classifier.rs` | Handler type identification |
| `src/opcode_table.rs` | Opcode ↔ handler mapping (serialize/deserialize) |
| `src/bytecode.rs` | Bytecode reader / operand decoder |
| `src/decrypt.rs` | `OpcodeCryptor` (CRC-based operand decryption) |
| `src/alu.rs` | NOR/NAND chain → ALU op reconstruction |
| `src/handler_semantic.rs` | VMP-semantic handler classification — `VmpSemantic` enum (~35 categories) + `SemanticMatcher` (8 multi-instruction fingerprints); test module `handler_semantic_tests.rs` is `#[path]`-included from here |
| `src/bin/cli.rs` | CLI |

~4 800 lines of Rust across 15 files (13 `src/*.rs` modules + `src/handler_semantic_tests.rs` test module + `src/bin/cli.rs`).

---

## Test status

`cargo test --all-targets` — 111 tests, all green (105 lib + 1 bin + 5 integration; up from 66, up from 16 originally). `cargo clippy --all-targets` — 0 warnings. This is a local-only research project — there is no CI. All four gates (`build`, `test`, `clippy --all-targets -- -D warnings`, `fmt --check`) must be run locally before commit. Tool configs (`rustfmt.toml`, `clippy.toml`, `deny.toml`) stay checked in for consistent local runs.

Integration tests (`tests/cli.rs`, via `assert_cmd`) exercise the compiled CLI binary against in-memory-fixture-backed PE files: default `--vip` resolution, the non-VMP exit-code gate, `--force-version` override (including its rejection of unknown values), and short-flag disambiguation as a regression guard.

Real end-to-end validation against VMP-protected sample binaries has **not been re-run since the current audit**. Earlier internal reports (`docs/VALIDATION_REPORT.md`) claim 22/22 samples pass, but they predate the audit. Take those numbers as historical, not current. VMP 1.x / 2.x detection is no longer a stub (see below), but no live x86 VMP-protected binary has been analyzed end-to-end with the current code.

---

## Development

```bash
cargo build                              # debug build
cargo test --all-targets                 # 111 tests (105 lib + 1 bin + 5 integration)
cargo clippy --all-targets -- -D warnings  # must be clean
cargo fmt --check                        # style is enforced project-wide (rustfmt.toml)
```

No CI. All four gates above are the developer's responsibility to run locally
before every commit. Supply-chain audits are also local: `cargo audit` and
`cargo deny check` (config: `deny.toml`) — run them when changing
dependencies.

---

## Known Limitations

1. **VMP 3.7+ (merged handlers) is not supported.** The classifier assumes one opcode → one handler entry, which breaks on 3.7+. See `docs/FUTURE_WORK.md`.
2. **Handler classifier covers only ~20 x86 first-byte patterns** out of the 256-opcode space; unknown handlers are labeled `UNKNOWN` with low confidence. A parallel VMP-semantic layer now exists alongside it: `HandlerClassification.vmp_semantic: Option<VmpSemantic>` (`src/handler_semantic.rs`), populated by `SemanticMatcher` against ~35 VMP handler categories. Currently **8 of ~35 are recognized** (`Rdtsc`, `Cpuid`, `Vmexit`, `Nand`, `Nor`, `Push`, `Pop`, `Vjmp`); the rest fall back to `None` and the legacy x86-instruction-level `handler_type` label. True-positive rate against real VMP-protected binaries is unverified — no live sample has been run through the matcher yet. Tracked as Q2.
3. **ALU chains ARE reconstructed** on the last instruction of a NOR/NAND run (`alu::reconstruct_alu_chains`, wired into `VmpDevirtualizer::devirtualize_range`), and `decompose_chain` returns symbolic stack-slot names (`"vsp+0"`, `"vsp+8"`) rather than the old `"stack_val_1"`/`"stack_val_2"` placeholders. What remains open: the underlying chain-pattern table (which byte sequences count as a NOR/NAND chain) is unvalidated against real VMP samples, and slot naming is hardcoded to the x64 stack convention. Tracked as Q3 / Days 6-7 in `AUDIT_REPORT.md`.
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
