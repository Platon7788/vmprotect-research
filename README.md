# VMP Devirtualizer

Rust CLI + library for analyzing VMProtect-obfuscated binaries. Loads PE binaries, locates the VM dispatch table, extracts and classifies handlers, and decodes bytecode into a JSON/text trace.

> **Status:** research prototype. Reliable path is **VMP 3.0-3.6** (with a valid dispatch-table RVA). VMP 1.x / 2.x detection is heuristic-only; VMP 3.7+ (merged handlers) is not supported. See [Known Limitations](#known-limitations) and [`AUDIT_REPORT.md`](./AUDIT_REPORT.md).

---

## Features

- PE loader (Windows + Linux ELF via `goblin`), with dual-bitness support (x86 PE32 + x86-64 PE32+)
- VM version heuristics — scored rule cascade over entry-stub bytes, `.vmp0`/`.vmp1` section layout, and auxiliary markers, returning a version + 0-100 confidence
- Dispatch-table locator (256-entry pointer table scan + optional `--dispatch-rva` hint)
- Handler classifier (x86 / x86-64 first-byte + REX-prefix patterns, bitness-gated)
- Optional Unicorn CPU-emulation extraction via Python `unicorn` subprocess
- ValueCryptor / CRC operand decryption
- ALU chain (NOR / NAND) → arithmetic op mapping
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
./target/release/vmp_devirt <binary> --vip 0x140001000 --format json
```

Full CLI reference: `vmp_devirt --help`.

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
| `src/bin/cli.rs` | CLI |

~2 800 lines of Rust across 13 files (12 `src/*.rs` modules + `src/bin/cli.rs`).

---

## Test status

`cargo test --lib` — 66 tests, all green (up from 16). `cargo clippy --all-targets` — 0 warnings. CI (`.github/workflows/ci.yml`) now runs build/test/clippy/fmt on a Windows + Linux matrix, plus a separate `cargo audit` + `cargo deny` security-audit job.

Real end-to-end validation against VMP-protected sample binaries has **not been re-run since the current audit**. Earlier internal reports (`docs/VALIDATION_REPORT.md`) claim 22/22 samples pass, but they predate the audit. Take those numbers as historical, not current. VMP 1.x / 2.x detection is no longer a stub (see below), but no live x86 VMP-protected binary has been analyzed end-to-end with the current code.

---

## Development

```bash
cargo build                        # debug build
cargo test --lib                   # 66 unit tests
cargo clippy --all-targets         # 0 warnings (CI enforces -D warnings)
cargo fmt --check                  # style is enforced project-wide (rustfmt.toml)
```

CI runs all four on every push/PR (`.github/workflows/ci.yml`), on a Windows + Linux matrix, with a separate `security-audit` job running `cargo audit` and `cargo deny check` (config: `deny.toml`).

---

## Known Limitations

1. **VMP 3.7+ (merged handlers) is not supported.** The classifier assumes one opcode → one handler entry, which breaks on 3.7+. See `docs/FUTURE_WORK.md`.
2. **Handler classifier covers only ~20 x86 first-byte patterns** out of the 256-opcode space; unknown handlers are labeled `UNKNOWN` with low confidence. The taxonomy is also still x86-instruction-level (`MOV_REG_REG`, `ADD_REG_REG`, ...), not VMP-semantic (`PUSH_VALUE`, `NOR_CHAIN`, ...) — mapping x86 patterns to VMP semantics is future work. Tracked as Q2.
3. **ALU decompose returns dummy stack-slot names** (`"stack_val_1"`, `"stack_val_2"`) rather than real symbolic slots, and isn't wired into the main devirtualization pipeline. Tracked as Q3.
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
