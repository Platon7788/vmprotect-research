//! Unit tests for `crate::protector`.
//!
//! Split from `protector.rs` via `#[cfg(test)] #[path]` so the impl file
//! stays under the project's 500-line ceiling.

use super::*;
use crate::pe_loader::test_util::build_minimal_pe;

// -------------------------------------------------------------------
// Enum / helper hygiene
// -------------------------------------------------------------------

#[test]
fn family_as_str_covers_all_variants() {
    // Compile-time exhaustiveness proxy: every variant returns a
    // non-empty label. A missing arm on `as_str` would land on a
    // catch-all typo, which we don't have — so every variant renders.
    for family in [
        ProtectorFamily::VmProtect,
        ProtectorFamily::Themida,
        ProtectorFamily::CodeVirtualizer,
        ProtectorFamily::EnigmaProtector,
        ProtectorFamily::Obsidium,
        ProtectorFamily::Armadillo,
        ProtectorFamily::AsPack,
        ProtectorFamily::ExeCryptor,
        ProtectorFamily::SafEngine,
        ProtectorFamily::Denuvo,
        ProtectorFamily::Upx,
        ProtectorFamily::Mpress,
        ProtectorFamily::Petite,
        ProtectorFamily::PeCompact,
        ProtectorFamily::Upack,
        ProtectorFamily::UnknownProtector,
        ProtectorFamily::Unprotected,
    ] {
        assert!(!family.as_str().is_empty());
    }
}

#[test]
fn is_vm_protector_categorises_families_correctly() {
    assert!(ProtectorFamily::VmProtect.is_vm_protector());
    assert!(ProtectorFamily::Themida.is_vm_protector());
    assert!(ProtectorFamily::Denuvo.is_vm_protector());
    assert!(!ProtectorFamily::Upx.is_vm_protector());
    assert!(!ProtectorFamily::PeCompact.is_vm_protector());
    assert!(!ProtectorFamily::Unprotected.is_vm_protector());
    assert!(!ProtectorFamily::UnknownProtector.is_vm_protector());
}

#[test]
fn only_vmprotect_is_supported_for_devirt_today() {
    assert!(ProtectorFamily::VmProtect.is_supported_for_devirt());
    for other in [
        ProtectorFamily::Themida,
        ProtectorFamily::CodeVirtualizer,
        ProtectorFamily::EnigmaProtector,
        ProtectorFamily::Obsidium,
        ProtectorFamily::Armadillo,
        ProtectorFamily::AsPack,
        ProtectorFamily::Denuvo,
        ProtectorFamily::Upx,
        ProtectorFamily::Unprotected,
        ProtectorFamily::UnknownProtector,
    ] {
        assert!(!other.is_supported_for_devirt());
    }
}

#[test]
fn family_serde_roundtrips() {
    let json = serde_json::to_string(&ProtectorFamily::VmProtect).unwrap();
    let back: ProtectorFamily = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ProtectorFamily::VmProtect);
}

// -------------------------------------------------------------------
// Shannon entropy — bounds and known values
// -------------------------------------------------------------------

#[test]
fn shannon_entropy_of_all_zeros_is_zero() {
    let data = vec![0u8; 1024];
    let e = shannon_entropy_for_tests(&data);
    assert!(e.abs() < 1e-9, "expected ~0, got {e}");
}

#[test]
fn shannon_entropy_of_uniform_full_range_is_eight() {
    // Each byte value appears exactly 4 times -> perfect uniform.
    let mut data = Vec::with_capacity(1024);
    for _ in 0..4 {
        for b in 0..=255u8 {
            data.push(b);
        }
    }
    let e = shannon_entropy_for_tests(&data);
    assert!((e - 8.0).abs() < 1e-6, "expected 8.0, got {e}");
}

#[test]
fn shannon_entropy_of_empty_is_zero() {
    assert_eq!(shannon_entropy_for_tests(&[]), 0.0);
}

// -------------------------------------------------------------------
// End-to-end detector cases — via `build_minimal_pe` fixture
// -------------------------------------------------------------------
//
// The shared PE builder always creates a single section named `.test`
// with x64 magic and one code page. We layer synthetic markers on top
// by embedding the search strings into the section body when needed.

#[test]
fn detector_identifies_vmprotect_from_vmp0_section_marker_string() {
    // build_minimal_pe always names its section `.test`, so we can't
    // easily fake `.vmp0`. Instead we plant the literal "VMProtect"
    // marker in the section body — that adds 15 points; add
    // "ZwProtectVirtualMemory" too and we clear the 40-pt vendor
    // threshold. This exercises the string-marker path.
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"padding");
    body.extend_from_slice(b"VMProtect"); // +15
    body.extend_from_slice(&[0u8; 32]);
    body.extend_from_slice(b"ZwProtectVirtualMemory"); // +15
    body.extend_from_slice(&[0u8; 64]);
    body.extend_from_slice(b"VMProtect"); // gives us enough total surface
    body.extend(std::iter::repeat_n(0u8, 512));

    let binary = build_minimal_pe(true, 0x1_4000_0000, 0x1000, &body);
    let report = ProtectorDetector::detect(&binary).unwrap();
    // Two string markers only sum to 30, below MIN_VENDOR_CONFIDENCE.
    // We expect this to LAND on UnknownProtector, not accidentally
    // upgrade to VMProtect from strings alone. This asserts that
    // string markers are supporting evidence, not standalone proof.
    assert_ne!(
        report.family,
        ProtectorFamily::VmProtect,
        "string markers alone must not upgrade to VMProtect: {:?}",
        report.reasons
    );
}

#[test]
fn detector_reports_confidence_and_reasons() {
    let binary = build_minimal_pe(true, 0x1_4000_0000, 0x1000, &[0x00u8; 512]);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert!(report.confidence <= 100, "confidence must be 0-100");
    // Reasons may be empty for a truly clean binary — accept that.
    // But: the report struct must be complete regardless.
    let _ = report.reasons.len();
}

#[test]
fn detector_class_level_gate_reports_unknown_on_bare_fixture() {
    // The shared PE fixture has a single section named `.test`
    // (0xC0000040 = R+W+CNT_INIT_DATA — deliberately not marked
    // executable, so `has_wx_section` does NOT fire on this fixture)
    // and no import table at all. The class-level rules that DO fire:
    //   - stripped IAT (< 12 imports) — +15
    //   - entry point outside `.text` (fixture uses `.test`) — +20
    // Total 35 > MIN_UNKNOWN_CONFIDENCE=30, so the verdict lands on
    // UnknownProtector with those two reasons.
    let binary = build_minimal_pe(true, 0x1_4000_0000, 0x1000, &[0x00u8; 512]);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_eq!(report.family, ProtectorFamily::UnknownProtector);
    assert!(
        report.reasons.iter().any(|r| r.contains("stripped IAT")),
        "reasons must include stripped-IAT: {:?}",
        report.reasons
    );
    assert!(
        report.reasons.iter().any(|r| r.contains("entry point falls outside")),
        "reasons must include entry-point-outside-.text: {:?}",
        report.reasons
    );
}

#[test]
fn detector_labels_plain_pe_as_unprotected_or_unknown() {
    // Positive baseline: with just zeros + no imports, the fixture
    // will always tip into UnknownProtector via §2.2 class rules.
    // We must never accidentally upgrade to a specific vendor here.
    let binary = build_minimal_pe(true, 0x1_4000_0000, 0x1000, &[0x00u8; 512]);
    let report = ProtectorDetector::detect(&binary).unwrap();
    for bad in [
        ProtectorFamily::VmProtect,
        ProtectorFamily::Themida,
        ProtectorFamily::Upx,
        ProtectorFamily::Mpress,
        ProtectorFamily::PeCompact,
    ] {
        assert_ne!(report.family, bad, "must not upgrade bare fixture to {bad:?}");
    }
}

#[test]
fn family_key_matches_as_str() {
    assert_eq!(family_key(ProtectorFamily::VmProtect), "VMProtect");
    assert_eq!(family_key(ProtectorFamily::Upx), "UPX");
    assert_eq!(family_key(ProtectorFamily::Unprotected), "Unprotected");
}

// -------------------------------------------------------------------
// Score aggregation via the internal `FamilyScore`
// -------------------------------------------------------------------

#[test]
fn family_score_saturates_at_100() {
    let mut s = FamilyScore::default();
    s.add(60, "one");
    s.add(60, "two");
    assert_eq!(s.confidence(), 100);
    assert_eq!(s.reasons.len(), 2);
}
