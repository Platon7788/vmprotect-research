# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

`Cargo.toml` still reads `0.1.0` — not bumped by this sweep. Commits `42cb238` (E)
through `a4e135b` (V), documented in full in `AUDIT_REPORT.md` §1c and
`RESEARCH_GAPS.md` §7.

### Added

- `ProtectorFamily` enum + `ProtectorDetector` + class-level "some protector"
  gate (entropy / W+X / stripped-IAT / EP-outside-`.text`) (`42cb238`, E).
- 10 vendor byte-table matchers: Themida/WinLicense, Enigma, Obsidium,
  Armadillo, ASPack, Code Virtualizer, Denuvo (detect + refuse), BattlEye,
  Vanguard, plus 5 compressor families (UPX/MPRESS/Petite/PECompact/Upack)
  (`94f1af8` F, `42cb238` E).
- Extended `VmpSemantic` matchers from 8 to the full 35/35 taxonomy
  (`505bfed` G, `5f42752` L, `59908c6` O).
- `JunkStripper` peephole passes Groups A-G (dead-store elimination, constant
  folding, backward liveness) with fixed-point iteration (`8bd4805`/`ea49498`
  H, `6a5d768` P).
- Structural VMP dispatcher fingerprint scanner for renamed-section VMP
  (BattlEye BEDaisy, EAC) (`832ffc4`, I).
- `register_roles` module: VIP/VSP/VKEY voter with a cross-handler
  consistency gate (`92c04af` K, `0c10fdd` Q).
- `CryptoScheme` per-VMP-version dispatch (`None`/`Placeholder`/
  `Vmp2Rolling`/`Vmp3PerHandler`) (`796da51`, M).
- `--features real-samples` harness: `tests/samples.rs` + `tests/fixtures/`
  scaffold (`d320477`, N).
- `--features synthetic-samples` E2E harness: `src/synthetic_sample.rs` PE
  generator + `tests/synthetic.rs`, 4 end-to-end tests validating the full
  pipeline structurally without real binaries (`8932073`, S).
- `--export-analysis <FILE>` unified JSON export: family + version +
  confidence + dispatch + register roles + handler classifications + crypto
  scheme + coverage % (`b1c3ccd`, R).
- Confidence scoring on `VmpSemantic` classifications (`b1c3ccd`, R).
- `VmpVersionDetail` with sub-version hints for VMP 3.6+/3.8+/3.10.5
  (`0c10fdd`, Q).
- `EXIT_UNSUPPORTED_FAMILY` = 3 for detected-but-unsupported vendor families
  (`42cb238`, E).
- `sanitise_section_name` log-injection sanitiser (`337a4fb`, J; extended to
  `protector_signals.rs` in `738bbf9`, T).

### Changed

- **BREAKING**: `HandlerClassification` gains a `vmp_semantic_confidence: u8`
  field (`b1c3ccd`, R).
- Version detector tiebreak made deterministic — ties are now resolved by
  candidate array order instead of `Iterator::max_by`'s implicit
  "last of equals," and logged when they occur (`337a4fb`, J).
- `has_xor_reg_imm` broadened from imm8-only to imm32 + reg-reg XOR forms
  (`738bbf9`, T).
- `Ret` / `Vemit` confidence tiers corrected (`Ret` 90, `Vemit` 88, both above
  `Vjmp`'s 85) (`738bbf9`, T).
- `handler_agreement` denominator now counts only voting handlers, not
  silent ones (`738bbf9`, T).
- `Vsetvsp` shape documented as unreachable on live handlers once `Vnop`
  runs first (`738bbf9`, T).

### Fixed

- Log-injection at `protector_signals.rs:138` — the structural dispatcher
  scanner added in `I` did not route section names through
  `sanitise_section_name` (`738bbf9`, T).
- `has_xor_reg_imm` was narrower than intended (imm8-only) (`738bbf9`, T).
- `Ret`/`Vemit`/`Popstk`/`Pushstk` confidence scoring was inverted
  (`738bbf9`, T).
- Register-role consistency denominator was too strict (`738bbf9`, T).
- Two tautological detector tests replaced with real behavioral assertions
  (`267607b`, U).
- Duplicate `junk_stripper` test removed (`267607b`, U).
- Synthetic-sample harness `FROZEN_ESSENTIALS` floor tightened (`267607b`, U).

### Removed

- `ProtectorFamily::ExeCryptor` / `SafEngine` variants — neither ever emitted
  a detection rule (`a4e135b`, V).
- `pub fn family_key` — thin wrapper over `as_str` (`a4e135b`, V).
- Crate-root re-exports of `VmpVersionDetail` and `HandlerCounts` — now
  internal-only (`a4e135b`, V).
- GitHub Actions CI (session 2026-07-27) — project is local-only.

### Test quality

- +204 tests since [0.2.0]: 111 → 315 default (`cargo test --all-targets`);
  322 under `--features synthetic-samples --all-targets`.
- Two tautologies replaced with real behavioral assertions.
- One duplicate test removed.
- Synthetic-sample floor tightened (`FROZEN_ESSENTIALS`).

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

[Unreleased]: https://github.com/Platon7788/vmprotect-research/compare/a4e135b...HEAD
[0.2.0]: https://github.com/Platon7788/vmprotect-research/compare/cbb6186...5744974
