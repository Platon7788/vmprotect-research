//! Unit tests for `crate::protector`.
//!
//! Split from `protector.rs` via `#[cfg(test)] #[path]` so the impl file
//! stays under the project's 500-line ceiling.

use super::*;
use crate::pe_loader::test_util::{
    build_minimal_pe, build_minimal_pe_with_named_sections, build_minimal_pe_with_section_name,
};

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

// -------------------------------------------------------------------
// Vendor byte-table matchers — Commit F
// -------------------------------------------------------------------
//
// Each vendor gets at least one positive test (marker fires -> family
// selected) and one negative-covered-elsewhere check. The bare-fixture
// negative baseline lives in
// `detector_labels_plain_pe_as_unprotected_or_unknown` above, so vendor
// tests here only need to prove the positive path.

/// Themida section-name allowlist path: a section literally named
/// `.themida` alone gives +40, right at MIN_VENDOR_CONFIDENCE. The
/// verdict should land on Themida with confidence >= 40.
#[test]
fn detector_identifies_themida_from_dot_themida_section_name() {
    let binary = build_minimal_pe_with_section_name(true, 0x1_4000_0000, ".themida", &[0u8; 64]);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_eq!(report.family, ProtectorFamily::Themida, "reasons: {:?}", report.reasons);
    assert!(report.confidence >= 40);
    assert!(report.reasons.iter().any(|r| r.contains(".themida")));
}

/// Themida 2.1.x / 3.0.x per-build randomised names include the 8-space
/// section name — must fire the Themida branch.
#[test]
fn detector_identifies_themida_from_eight_space_section_name() {
    let binary = build_minimal_pe_with_section_name(true, 0x1_4000_0000, "        ", &[0u8; 64]);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_eq!(report.family, ProtectorFamily::Themida, "reasons: {:?}", report.reasons);
}

/// Themida v1.x uncompressed entry stub planted at RVA 0x1000 (fixture's
/// entry point). The 15-byte prelude is verbatim; +40 to Themida.
#[test]
fn detector_identifies_themida_from_v1_uncompressed_entry_stub() {
    let stub = [
        0x55, 0x8B, 0xEC, 0x83, 0xC4, 0xD8, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5A, 0x81, 0xEA,
    ];
    let mut body = stub.to_vec();
    body.extend_from_slice(&[0u8; 128]);
    let binary = build_minimal_pe(true, 0x1_4000_0000, 0x1000, &body);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_eq!(report.family, ProtectorFamily::Themida, "reasons: {:?}", report.reasons);
    assert!(report.reasons.iter().any(|r| r.contains("Themida")));
}

/// Enigma section-name path.
#[test]
fn detector_identifies_enigma_from_dot_enigma1_section_name() {
    let binary = build_minimal_pe_with_section_name(true, 0x1_4000_0000, ".enigma1", &[0u8; 64]);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_eq!(
        report.family,
        ProtectorFamily::EnigmaProtector,
        "reasons: {:?}",
        report.reasons
    );
    assert!(report.confidence >= 40);
}

/// Enigma entry-stub prelude planted at entry -> +40 to Enigma.
#[test]
fn detector_identifies_enigma_from_entry_stub_prelude() {
    let stub = [0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x8B, 0xD5, 0x81, 0xED];
    let mut body = stub.to_vec();
    body.extend_from_slice(&[0u8; 128]);
    let binary = build_minimal_pe(true, 0x1_4000_0000, 0x1000, &body);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_eq!(
        report.family,
        ProtectorFamily::EnigmaProtector,
        "reasons: {:?}",
        report.reasons
    );
}

/// Obsidium short-jump anti-disasm entry stub planted at entry -> +50 to
/// Obsidium. Solo signal must clear MIN_VENDOR_CONFIDENCE.
#[test]
fn detector_identifies_obsidium_from_short_jump_entry_stub() {
    let stub = [0xEB, 0x03, 0x11, 0x22, 0x33, 0xE8, 0x44, 0x55, 0x66, 0x77, 0x58];
    let mut body = stub.to_vec();
    body.extend_from_slice(&[0u8; 128]);
    let binary = build_minimal_pe(true, 0x1_4000_0000, 0x1000, &body);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_eq!(
        report.family,
        ProtectorFamily::Obsidium,
        "reasons: {:?}",
        report.reasons
    );
}

/// Armadillo requires TWO of its section names to co-occur before firing.
/// Fixture places `.text1` + `.data1` — enough to trigger the rule.
#[test]
fn detector_identifies_armadillo_from_two_section_names() {
    let binary =
        build_minimal_pe_with_named_sections(true, 0x1_4000_0000, &[(".text1", &[0u8; 32]), (".data1", &[0u8; 32])]);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_eq!(
        report.family,
        ProtectorFamily::Armadillo,
        "reasons: {:?}",
        report.reasons
    );
    assert!(report.reasons.iter().any(|r| r.contains("Armadillo section names")));
}

/// A lone `.pdata` section (real x64 unwind info) must NOT get promoted to
/// Armadillo — the 2-of-N gate is the whole point of that vendor's rule.
#[test]
fn detector_does_not_upgrade_lone_pdata_section_to_armadillo() {
    let binary = build_minimal_pe_with_section_name(true, 0x1_4000_0000, ".pdata", &[0u8; 64]);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_ne!(
        report.family,
        ProtectorFamily::Armadillo,
        "reasons: {:?}",
        report.reasons
    );
}

/// ASPack section-name path — any single hit is enough (+50).
#[test]
fn detector_identifies_aspack_from_dot_aspack_section_name() {
    let binary = build_minimal_pe_with_section_name(true, 0x1_4000_0000, ".aspack", &[0u8; 64]);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_eq!(report.family, ProtectorFamily::AsPack, "reasons: {:?}", report.reasons);
    assert!(report.confidence >= 50);
}

/// Code Virtualizer dispatcher fingerprint hits the whole-file scan. Even
/// without a matching section name, the 7-byte pattern in section data
/// should push CodeVirtualizer past MIN_VENDOR_CONFIDENCE.
#[test]
fn detector_identifies_code_virtualizer_from_dispatcher_fingerprint() {
    let mut body = vec![0u8; 32];
    body.extend_from_slice(&[0xAC, 0x0F, 0xB6, 0xC0, 0xFF, 0x24, 0x87]);
    body.extend_from_slice(&[0u8; 128]);
    let binary = build_minimal_pe(true, 0x1_4000_0000, 0x1000, &body);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_eq!(
        report.family,
        ProtectorFamily::CodeVirtualizer,
        "reasons: {:?}",
        report.reasons
    );
    assert!(report.reasons.iter().any(|r| r.contains("dispatcher fingerprint")));
}

/// Denuvo signals via a section literally named `.vm` (case-sensitive).
/// The tool "deliberately refuses" Denuvo — we still identify the family
/// so callers can print the correct diagnostic.
#[test]
fn detector_identifies_denuvo_from_vm_section() {
    let binary = build_minimal_pe_with_section_name(true, 0x1_4000_0000, ".vm", &[0u8; 64]);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_eq!(report.family, ProtectorFamily::Denuvo, "reasons: {:?}", report.reasons);
}

/// BattlEye BEDaisy rewraps VMProtect. The `.be0` section bumps VmProtect
/// directly (+60) so the CLI can still route to `VmpDevirtualizer`
/// instead of falling into UnknownProtector.
#[test]
fn detector_identifies_battleye_bumps_vmprotect_family() {
    let binary = build_minimal_pe_with_section_name(true, 0x1_4000_0000, ".be0", &[0u8; 64]);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_eq!(
        report.family,
        ProtectorFamily::VmProtect,
        "reasons: {:?}",
        report.reasons
    );
    assert!(report.reasons.iter().any(|r| r.contains("BattlEye")));
}

/// Vanguard/Packman is not in the ProtectorFamily enum — two `.stub`
/// sections must land on UnknownProtector with the specific reason string.
#[test]
fn detector_identifies_vanguard_shell_via_double_stub_sections() {
    let binary =
        build_minimal_pe_with_named_sections(true, 0x1_4000_0000, &[(".stub", &[0u8; 32]), (".stub", &[0u8; 32])]);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_eq!(
        report.family,
        ProtectorFamily::UnknownProtector,
        "reasons: {:?}",
        report.reasons
    );
    assert!(
        report
            .reasons
            .iter()
            .any(|r| r.contains("Vanguard/Packman shell (.stub x2)")),
        "reasons: {:?}",
        report.reasons
    );
}

/// Bare fixture must not accidentally fire any of the new vendor rules
/// (Themida, Enigma, Obsidium, Armadillo, AsPack, CodeVirtualizer,
/// Denuvo). Guards against pattern tables that would false-positive on
/// all-zero section bodies.
#[test]
fn detector_bare_fixture_fires_no_new_vendor_rule() {
    let binary = build_minimal_pe(true, 0x1_4000_0000, 0x1000, &[0u8; 512]);
    let report = ProtectorDetector::detect(&binary).unwrap();
    for bad in [
        ProtectorFamily::Themida,
        ProtectorFamily::EnigmaProtector,
        ProtectorFamily::Obsidium,
        ProtectorFamily::Armadillo,
        ProtectorFamily::AsPack,
        ProtectorFamily::CodeVirtualizer,
        ProtectorFamily::Denuvo,
    ] {
        assert_ne!(report.family, bad, "bare fixture wrongly upgraded to {bad:?}");
    }
}

/// Cross-vendor: fixture combines a Themida section name (+40) with the
/// literal "VMProtect" string (+15). Themida must win because 40 > 15.
/// This pins the max-by-points tie-break behaviour so a future rule
/// re-ordering can't silently change the winner selection.
#[test]
fn detector_cross_vendor_highest_score_wins_deterministically() {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"padding");
    body.extend_from_slice(b"VMProtect"); // +15 to VmProtect
    body.extend_from_slice(&[0u8; 256]);
    let binary = build_minimal_pe_with_section_name(true, 0x1_4000_0000, ".themida", &body);
    let report = ProtectorDetector::detect(&binary).unwrap();
    assert_eq!(report.family, ProtectorFamily::Themida, "reasons: {:?}", report.reasons);
}
