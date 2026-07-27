# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.2.0] - 2026-07-27 (planned — not yet tagged; `Cargo.toml` still reads `0.1.0`)

Commits: `b95246d`, `06ae816`, `64288a4`, `e586638`, `e5fa959`, `5744974`. Full context in
`AUDIT_REPORT.md` §1b.

### Added

- `--force-version <vmp1|vmp2|vmp30|vmp35|vmp36>` CLI flag for research overrides (`b95246d`).
- `EXIT_NOT_VMP` (exit code 2) for binaries the detector confidently rejects (`b95246d`).
- `PEBinary::entry_point_va()` public method (`b95246d`).
- `VmpVersion` enum re-exported at crate root (`b95246d`).
- `VmpSemantic` enum covering ~35 VMP handler categories (`06ae816`).
- `SemanticMatcher` with 8 fingerprints (Rdtsc, Cpuid, Vmexit, Nand, Nor, Push, Pop, Vjmp) (`06ae816`).
- `HandlerClassification.vmp_semantic: Option<VmpSemantic>` field, `#[serde(default)]` for backward compatibility (`06ae816`).
- `SemanticMatcher`, `VmpSemantic` re-exported at crate root (`06ae816`).
- `DecodedInstruction.alu_op: Option<ALUOp>` field, populated by ALU chain reconstruction (`64288a4`).
- `VmpDevirtualizer::force_version(VmpVersion)` and `looks_like_vmp() -> bool` methods (`b95246d`, `5744974`).
- `pe_loader::test_util::build_minimal_pe` public-in-tests fixture builder (`5744974`).
- Integration test harness (`tests/cli.rs` + `tests/common/mod.rs`) via `assert_cmd` (`b95246d`).

### Changed

- **BREAKING**: `Bytecode::decode_operands` now takes `cryptor: &mut OpcodeCryptor` (`64288a4`). Any downstream consumer must construct one via `OpcodeCryptor::new()` + `init_from_section(start_vip)` and reuse it across the whole `devirtualize_range` call — VMP's operand cipher is stateful across the bytecode stream.
- Default `--vip` is now the PE entry point instead of hardcoded `0x140001000` (`b95246d`).
- `alu::decompose_chain` returns `"vsp+0"` / `"vsp+8"` (was `"stack_val_1"` / `"stack_val_2"`) (`64288a4`).
- Non-VMP-detected binaries exit `2` with an actionable stderr message instead of attempting devirtualization (`b95246d`).

### Fixed (Commit A — audit-driven, `e586638`)

- Sign-extension in the H_JMP handler: negative `rel32` was zero-extended, producing +4GB forward jumps for every backward VMP jump.
- `read_imm` shift-overflow at size ≥ 9: adversarial handler tables can no longer trigger a debug panic / release UB.
- Off-by-one in the dispatch-table pattern scan: exactly-256×entry_size sections are now detected.
- `OpcodeTable::from_json` panic on short `opcode_byte` strings — now returns `Err`.
- 1-NOR chain → `ALUOp::Not` was silently dropped; `reconstruct_alu_chains` now uses `match_chain` to handle all registered chain lengths.
- `version::section_at_va` clamps to `min(virtual_size, size_of_raw_data)`, matching `pe_loader::locate_section`.
- `entry_point_bytes` uses `read_bytes_up_to`, so short entry sections no longer silently skip all VMP1 heuristics.

### Removed

- Crate-root re-exports of `DispatchExtractorPy` and `DispatchEntry`. Access via `vmp_devirt::dispatch_extractor_py::*`. Preparation for Q15 (pure-Rust replacement) as a non-breaking change (`5744974`).
- `alu::HandlerContext` struct — dead public API (`5744974`).
- `XorKeyAnalyzer::new` + fields — dead public API (`5744974`). `XorKeyAnalyzer` is now a bare marker type with only associated functions.

### Test quality

- +40 net new tests: 66 → 111 (Days 1-5 + audit-remediation; 105 lib + 1 bin + 5 integration).
- Deleted tautological `test_find_extractor_script` — rewrote as a real assertion (`e5fa959`).
- Implemented 3 previously-empty test stubs against the shared `test_util::build_minimal_pe` fixture (`5744974`).
- Tightened multiple assertions from `assert_ne!(_, Some(X))` to `assert_eq!(_, None)` — misclassifications no longer pass (`e5fa959`).
- `test_crc_update` now pins the exact `crc*31 + val` formula (`e5fa959`).
- Added round-trip tests for `decrypt_value_u32` / `decrypt_value_u64` (`e5fa959`).

## Earlier history

Commits before `b95246d` (audit-driven overhaul `cbb6186`, CI/supply-chain hardening `d81cfbd`, and
everything prior) predate this changelog and are documented only in `AUDIT_REPORT.md` §1 / §1a.

[Unreleased]: https://github.com/Platon7788/vmprotect-research/compare/5744974...HEAD
[0.2.0]: https://github.com/Platon7788/vmprotect-research/compare/cbb6186...5744974
