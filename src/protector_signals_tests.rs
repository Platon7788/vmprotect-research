//! Unit + end-to-end tests for the structural VMP dispatcher fingerprint
//! (Commit I).
//!
//! Split out via `#[cfg(test)] #[path]` -- same convention as
//! `protector.rs`'s own `protector_tests.rs` -- both to keep
//! `protector_signals.rs` under the crate's 500-line ceiling and to avoid
//! pushing the already-sizeable `protector_tests.rs` over it too.

use super::*;
use crate::pe_loader::test_util::build_minimal_pe_with_section_characteristics;
use crate::protector::{ProtectorDetector, ProtectorFamily};

/// `CNT_CODE | MEM_EXECUTE | MEM_READ` -- a realistic RX code section.
const RX: u32 = 0x6000_0020;
/// Same non-executable `Characteristics` value every other fixture builder
/// in this crate uses (R+W+CNT_INIT_DATA) -- used to prove the scan really
/// is gated on `MEM_EXECUTE` and not just "any section".
const RW_NOT_X: u32 = 0xC000_0040;

/// x64 encoding of the four-primitive dispatcher chain, verbatim:
/// `mov r64,[rsi]` (`49 8B 06`) / `xor rax,imm32` (`48 81 F0 imm32`) /
/// `add rax,[rip+0]` (`48 03 05 imm32`) / `jmp [rax]` (`FF 20`).
/// 19 bytes total -- comfortably inside the 64-byte scan window.
fn x64_dispatcher_bytes() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x49, 0x8B, 0x06]);
    v.extend_from_slice(&[0x48, 0x81, 0xF0, 0x11, 0x22, 0x33, 0x44]);
    v.extend_from_slice(&[0x48, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[0xFF, 0x20]);
    v
}

/// x86 encoding of the same chain, no REX prefixes: `mov eax,[esi]`
/// (`8B 06`) / `xor eax,imm32` (`81 F0 imm32`) / `add eax,[disp32]`
/// (`03 05 imm32`) / `jmp [eax]` (`FF 20`).
fn x86_dispatcher_bytes() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x8B, 0x06]);
    v.extend_from_slice(&[0x81, 0xF0, 0x11, 0x22, 0x33, 0x44]);
    v.extend_from_slice(&[0x03, 0x05, 0x00, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[0xFF, 0x20]);
    v
}

// -------------------------------------------------------------------
// `scan_rx_sections_for_dispatcher` unit tests
// -------------------------------------------------------------------

#[test]
fn scan_finds_x64_dispatcher_in_rx_section() {
    let mut body = x64_dispatcher_bytes();
    body.extend_from_slice(&[0u8; 128]);
    let binary = build_minimal_pe_with_section_characteristics(true, 0x1_4000_0000, &[(".text", &body, RX)]);
    assert!(scan_rx_sections_for_dispatcher(&binary).unwrap());
}

#[test]
fn scan_finds_x86_dispatcher_in_rx_section() {
    let mut body = x86_dispatcher_bytes();
    body.extend_from_slice(&[0u8; 128]);
    let binary = build_minimal_pe_with_section_characteristics(false, 0x40_0000, &[(".text", &body, RX)]);
    assert!(scan_rx_sections_for_dispatcher(&binary).unwrap());
}

/// Same bytes as the positive x64 case, but the section is NOT marked
/// `MEM_EXECUTE` -- the RX gate must skip it entirely, so no match.
#[test]
fn scan_ignores_non_executable_section_with_full_pattern() {
    let mut body = x64_dispatcher_bytes();
    body.extend_from_slice(&[0u8; 128]);
    let binary = build_minimal_pe_with_section_characteristics(true, 0x1_4000_0000, &[(".test", &body, RW_NOT_X)]);
    assert!(!scan_rx_sections_for_dispatcher(&binary).unwrap());
}

#[test]
fn scan_returns_false_for_plain_rx_section() {
    let body = vec![0u8; 256];
    let binary = build_minimal_pe_with_section_characteristics(true, 0x1_4000_0000, &[(".text", &body, RX)]);
    assert!(!scan_rx_sections_for_dispatcher(&binary).unwrap());
}

/// Only the first three primitives (mov / xor / add) -- no `FF /4`
/// anywhere in the section. Missing one of the four must not match.
#[test]
fn scan_returns_false_when_indirect_jmp_is_missing() {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x49, 0x8B, 0x06]);
    body.extend_from_slice(&[0x48, 0x81, 0xF0, 0x11, 0x22, 0x33, 0x44]);
    body.extend_from_slice(&[0x48, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00]);
    body.extend_from_slice(&[0u8; 128]);
    let binary = build_minimal_pe_with_section_characteristics(true, 0x1_4000_0000, &[(".text", &body, RX)]);
    assert!(!scan_rx_sections_for_dispatcher(&binary).unwrap());
}

/// Two 16-byte junk (NOP sled) gaps inserted between three of the four
/// steps -- total span (3 + 16 + 7 + 16 + 7 + 2 = 51 bytes) still fits the
/// 64-byte window. Proves the scan isn't looking for the four primitives
/// back-to-back.
#[test]
fn scan_tolerates_16_byte_junk_gaps_between_primitives() {
    let junk = [0x90u8; 16]; // NOP sled -- doesn't match any of the four shapes
    let mut body = Vec::new();
    body.extend_from_slice(&[0x49, 0x8B, 0x06]); // mov
    body.extend_from_slice(&junk);
    body.extend_from_slice(&[0x48, 0x81, 0xF0, 0x11, 0x22, 0x33, 0x44]); // xor
    body.extend_from_slice(&junk);
    body.extend_from_slice(&[0x48, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00]); // add
    body.extend_from_slice(&[0xFF, 0x20]); // jmp
    body.extend_from_slice(&[0u8; 128]);
    let binary = build_minimal_pe_with_section_characteristics(true, 0x1_4000_0000, &[(".text", &body, RX)]);
    assert!(scan_rx_sections_for_dispatcher(&binary).unwrap());
}

// -------------------------------------------------------------------
// End-to-end through `ProtectorDetector::detect`
// -------------------------------------------------------------------

#[test]
fn detector_identifies_vmprotect_from_structural_dispatcher_x64() {
    let mut body = x64_dispatcher_bytes();
    body.extend_from_slice(&[0u8; 128]);
    let binary = build_minimal_pe_with_section_characteristics(true, 0x1_4000_0000, &[(".text", &body, RX)]);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_eq!(
        report.family,
        ProtectorFamily::VmProtect,
        "reasons: {:?}",
        report.reasons
    );
    assert!(
        report.reasons.iter().any(|r| r.contains("structural VMP dispatcher")),
        "reasons: {:?}",
        report.reasons
    );
}

#[test]
fn detector_identifies_vmprotect_from_structural_dispatcher_x86() {
    let mut body = x86_dispatcher_bytes();
    body.extend_from_slice(&[0u8; 128]);
    let binary = build_minimal_pe_with_section_characteristics(false, 0x40_0000, &[(".text", &body, RX)]);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_eq!(
        report.family,
        ProtectorFamily::VmProtect,
        "reasons: {:?}",
        report.reasons
    );
}

/// A plain RX section with no dispatcher bytes must not trip the
/// structural rule -- verified via the reason string, since other
/// class-level signals may still push the verdict to `UnknownProtector`.
#[test]
fn detector_does_not_fire_structural_rule_on_plain_rx_section() {
    let body = vec![0u8; 256];
    let binary = build_minimal_pe_with_section_characteristics(true, 0x1_4000_0000, &[(".text", &body, RX)]);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert!(
        !report.reasons.iter().any(|r| r.contains("structural VMP dispatcher")),
        "reasons: {:?}",
        report.reasons
    );
}
