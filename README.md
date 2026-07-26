# VMP Devirtualizer

Rust CLI + library for analyzing VMProtect-obfuscated binaries. Loads PE binaries, locates the VM dispatch table, extracts and classifies handlers, and decodes bytecode into a JSON/text trace.

> **Status:** research prototype. Reliable path is **VMP 3.0-3.6** (with a valid dispatch-table RVA). VMP 1.x / 2.x detection is heuristic-only; VMP 3.7+ (merged handlers) is not supported. See [Known Limitations](#known-limitations) and [`AUDIT_REPORT.md`](./AUDIT_REPORT.md).

---

## Features

- PE loader (Windows + Linux ELF via `goblin`)
- VM version heuristics (`.vmp0` / `.vmp1` section fingerprints)
- Dispatch-table locator (256-entry pointer table scan + optional known-RVA hint)
- Handler classifier (x86-64 first-byte + REX-prefix patterns)
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
| `src/version.rs` | VMP-version heuristics |
| `src/dispatch_table.rs` | Dispatch-table locator + validator |
| `src/xor_key_analyzer.rs` | Static XOR-key extraction (256 entries) |
| `src/dispatch_extractor_py.rs` | Python-`unicorn` subprocess bridge |
| `src/handler_classifier.rs` | Handler type identification |
| `src/opcode_table.rs` | Opcode ↔ handler mapping (serialize/deserialize) |
| `src/bytecode.rs` | Bytecode reader / operand decoder |
| `src/decrypt.rs` | `OpcodeCryptor` (CRC-based operand decryption) |
| `src/alu.rs` | NOR/NAND chain → ALU op reconstruction |
| `src/bin/cli.rs` | CLI |

~2 800 lines of Rust across 11 modules.

---

## Test status

`cargo test --lib` — 16 tests, all green. Note: **7 of 16 are stubs** (require real PE fixtures, tracked in `AUDIT_REPORT.md` §Q13). Real coverage of the analysis pipeline is ≈15 %.

Real end-to-end validation against VMP-protected sample binaries has **not been re-run since the current audit**. Earlier internal reports (`docs/VALIDATION_REPORT.md`) claim 22/22 samples pass, but they predate the audit and the underlying VMP 1.x / 2.x detection is currently a stub (see below). Take those numbers as historical, not current.

---

## Known Limitations

1. **VMP 1.x / 2.x version detection is a stub.** `has_vmp1_sections` and `has_vmp2_sections` currently return `false` unconditionally (`src/version.rs`). Binaries of these versions will be reported as `Unknown`. Tracked as C1 in `AUDIT_REPORT.md`.
2. **`Bytecode::size()` returns a fixed `5`** (`src/bytecode.rs`). This means `devirtualize_range` advances 5 bytes per instruction regardless of actual handler size — output beyond the first instruction is unreliable. Tracked as C3.
3. **Dispatch table locator uses a hard-coded RVA `0x48138` as first guess** (`src/dispatch_table.rs`). Fallback pattern-scan runs only if the hard-coded RVA is outside all sections. Tracked as C4.
4. **VMP 3.7+ (merged handlers) is not supported.** The classifier assumes one opcode → one handler entry, which breaks on 3.7+. See `docs/FUTURE_WORK.md`.
5. **Python subprocess dependency** for the Unicorn extraction path. Not required — the code falls back to static analysis — but reduces fidelity when absent.
6. **Handler classifier covers only ~20 x86 first-byte patterns**; unknown handlers are labeled `UNKNOWN` with low confidence. Tracked as Q2.
7. **ALU decompose returns dummy stack-slot names** (`"stack_val_1"`, `"stack_val_2"`) rather than real symbolic slots. Tracked as Q3.

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
