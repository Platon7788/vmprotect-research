//! Unit tests for [`crate::version`].
//!
//! Split from `version.rs` via `#[cfg(test)] #[path]` to keep that file
//! under the crate's 500-line ceiling (see `handler_semantic_tests.rs` /
//! `junk_stripper_tests.rs` / `protector_tests.rs` for the same pattern
//! elsewhere in this crate).

use super::*;
use crate::version_matchers::{
    CALL_REL32, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, MOV_ESI_IMM32, PUSH_IMM32,
};

#[test]
fn test_version_string() {
    assert_eq!(VmpVersion::Vmp35.as_str(), "VMP 3.5.0-3.5.1");
    assert_eq!(VmpVersion::Vmp36Plus.as_str(), "VMP 3.6-3.10.5");
}

#[test]
fn test_entry_stub_matcher_exact_match() {
    let data = [0x68, 0x11, 0x22, 0x33, 0x44];
    assert!(EntryStubMatcher::matches(&data, &PUSH_IMM32));
}

#[test]
fn test_entry_stub_matcher_rejects_wrong_opcode() {
    let data = [0x90, 0x11, 0x22, 0x33, 0x44];
    assert!(!EntryStubMatcher::matches(&data, &PUSH_IMM32));
}

#[test]
fn test_entry_stub_matcher_rejects_short_data() {
    let data = [0x68, 0x11];
    assert!(!EntryStubMatcher::matches(&data, &PUSH_IMM32));
}

#[test]
fn test_entry_stub_matcher_wildcard_bytes_ignored() {
    let a = [0xBE, 0x00, 0x00, 0x00, 0x00];
    let b = [0xBE, 0xFF, 0xFF, 0xFF, 0xFF];
    assert!(EntryStubMatcher::matches(&a, &MOV_ESI_IMM32));
    assert!(EntryStubMatcher::matches(&b, &MOV_ESI_IMM32));
}

#[test]
fn test_find_locates_pattern_mid_buffer() {
    let data = [0x90, 0x90, 0x90, 0xE8, 0x01, 0x02, 0x03, 0x04];
    let offset = EntryStubMatcher::find(&data, &CALL_REL32, 16);
    assert_eq!(offset, Some(3));
}

#[test]
fn test_find_returns_none_when_absent() {
    let data = [0x90, 0x90, 0x90, 0x90];
    assert_eq!(EntryStubMatcher::find(&data, &CALL_REL32, 16), None);
}

#[test]
fn test_find_vmp1_stub_detects_pushad_and_mov_esi() {
    let mut data = vec![0x60]; // pushad
    data.extend_from_slice(&[0x90, 0x90]); // padding
    data.push(0xBE);
    data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // mov esi, imm32
    let stub = EntryStubMatcher::find_vmp1_stub(&data, 16);
    assert!(stub.has_pushad);
    assert!(stub.has_mov_esi_imm32);
    assert!(!stub.has_lea_edi_esi);
}

#[test]
fn test_find_vmp1_stub_absent_without_pushad() {
    let data = [0x90, 0xBE, 0x01, 0x02, 0x03, 0x04];
    let stub = EntryStubMatcher::find_vmp1_stub(&data, 16);
    assert!(!stub.has_pushad);
    assert!(!stub.has_mov_esi_imm32);
}

#[test]
fn test_find_push_call_jmp_detects_call() {
    let mut data = vec![0x68, 0xAA, 0xBB, 0xCC, 0xDD]; // push imm32
    data.push(0xE8); // call rel32
    data.extend_from_slice(&10i32.to_le_bytes());
    let stub = EntryStubMatcher::find_push_call_jmp(&data, 16).expect("should match");
    assert_eq!(stub.push_offset, 0);
    assert!(stub.is_call);
    assert_eq!(stub.rel32, 10);
}

#[test]
fn test_find_push_call_jmp_detects_jmp() {
    let mut data = vec![0x68, 0xAA, 0xBB, 0xCC, 0xDD]; // push imm32
    data.push(0xE9); // jmp rel32
    data.extend_from_slice(&(-20i32).to_le_bytes());
    let stub = EntryStubMatcher::find_push_call_jmp(&data, 16).expect("should match");
    assert!(!stub.is_call);
    assert_eq!(stub.rel32, -20);
}

#[test]
fn test_find_push_call_jmp_returns_none_without_branch() {
    let data = [0x68, 0xAA, 0xBB, 0xCC, 0xDD, 0x90, 0x90, 0x90, 0x90, 0x90];
    assert!(EntryStubMatcher::find_push_call_jmp(&data, 16).is_none());
}

#[test]
fn test_section_layout_classify_both() {
    assert_eq!(SectionLayoutMatcher::classify(true, true), SectionLayout::Both);
}

#[test]
fn test_section_layout_classify_one_of() {
    assert_eq!(SectionLayoutMatcher::classify(true, false), SectionLayout::OneOf);
    assert_eq!(SectionLayoutMatcher::classify(false, true), SectionLayout::OneOf);
}

#[test]
fn test_section_layout_classify_neither() {
    assert_eq!(SectionLayoutMatcher::classify(false, false), SectionLayout::Neither);
}

#[test]
fn test_is_rwx() {
    assert!(is_rwx(IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE));
    assert!(!is_rwx(IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ));
}

#[test]
fn test_rule_score_accumulates_points_and_top_priority() {
    let mut score = RuleScore::default();
    score.add(20, RulePriority::Marker, "marker hit");
    score.add(40, RulePriority::EntryStub, "stub hit");
    assert_eq!(score.points, 60);
    assert_eq!(score.top_priority, Some(RulePriority::EntryStub));
    assert_eq!(score.confidence(), 60);
}

#[test]
fn test_rule_score_confidence_clamped_to_100() {
    let mut score = RuleScore::default();
    score.add(90, RulePriority::EntryStub, "a");
    score.add(90, RulePriority::EntryStub, "b");
    assert_eq!(score.confidence(), 100);
}

// ---------------------------------------------------------------------
// Q — Part B: VMP 3.x sub-version discrimination markers
// ---------------------------------------------------------------------

/// Build a minimal PE with a `.vmp0` section and an entry stub that
/// lands inside `.vmp0`, so the coarse detector settles on
/// [`VmpVersion::Vmp36Plus`]. `extra_string` is appended to the
/// `.rdata` payload — the sub-version markers pattern-match against
/// the raw file bytes, so any section containing the literal works.
///
/// Returns the loaded binary. All the Part-B tests share this shape
/// because the sub-hint filter only fires when the coarse bucket is
/// already in the 3.x range.
fn build_vmp36_binary_with_marker(extra_string: &[u8]) -> crate::PEBinary {
    use crate::pe_loader::test_util::build_minimal_pe_with_named_sections;

    let image_base = 0x1_4000_0000u64;
    let entry_va = image_base + 0x1000;
    // push imm32 (dummy) + call rel32 → target at RVA 0x2000 (start of .vmp0)
    let next_instr_va = entry_va + 10;
    let vmp0_va = image_base + 0x2000;
    let rel32 = (vmp0_va as i64 - next_instr_va as i64) as i32;

    let mut entry_stub = vec![0x68, 0x00, 0x00, 0x00, 0x00];
    entry_stub.push(0xE8);
    entry_stub.extend_from_slice(&rel32.to_le_bytes());

    let vmp0_data = [0u8; 16];

    // Bury the marker in a third section so it sits somewhere in the
    // raw file image the string scanner walks.
    build_minimal_pe_with_named_sections(
        true,
        image_base,
        &[(".text", &entry_stub), (".vmp0", &vmp0_data), (".rdata", extra_string)],
    )
}

#[test]
fn detector_detects_zw_protect_and_virtual_protect_pair_bumps_vmp36plus() {
    // Both API names present in the raw file — this is the 3.6+ tell
    // (see cyber.wtf writeup). The Zw* alone gives +10 to all three
    // 3.x buckets; the pair grants an additional +15 to Vmp36Plus and
    // must surface as a sub-hint.
    let marker = b"ZwProtectVirtualMemory\0VirtualProtect\0" as &[u8];
    let binary = build_vmp36_binary_with_marker(marker);

    let (detail, confidence) = VersionDetector::detect_detailed(&binary).expect("detect_detailed");
    assert_eq!(
        detail.version,
        VmpVersion::Vmp36Plus,
        "Zw+VirtualProtect pair on a One-Of-.vmpN layout must land on 3.6+"
    );
    assert!(confidence >= 40, "confidence {} must clear the threshold", confidence);
    assert!(
        detail.sub_hints.iter().any(|h| h.contains("ZwProtectVirtualMemory")),
        "sub_hints={:?} missing Zw+VirtualProtect pair hint",
        detail.sub_hints
    );
}

#[test]
fn detector_detects_ldr_load_dll_string_bumps_vmp36plus() {
    let marker = b"LdrLoadDll\0" as &[u8];
    let binary = build_vmp36_binary_with_marker(marker);

    let (detail, _confidence) = VersionDetector::detect_detailed(&binary).expect("detect_detailed");
    assert_eq!(detail.version, VmpVersion::Vmp36Plus);
    assert!(
        detail.sub_hints.iter().any(|h| h.contains("LdrLoadDll")),
        "sub_hints={:?} missing LdrLoadDll (VMP 3.8+) hint",
        detail.sub_hints
    );
}

#[test]
fn detector_detects_rtl_add_function_table_string_bumps_vmp36plus() {
    let marker = b"RtlAddFunctionTable\0" as &[u8];
    let binary = build_vmp36_binary_with_marker(marker);

    let (detail, _confidence) = VersionDetector::detect_detailed(&binary).expect("detect_detailed");
    assert_eq!(detail.version, VmpVersion::Vmp36Plus);
    assert!(
        detail.sub_hints.iter().any(|h| h.contains("RtlAddFunctionTable")),
        "sub_hints={:?} missing RtlAddFunctionTable (VMP 3.10.5) hint",
        detail.sub_hints
    );
}

#[test]
fn detect_wrapper_discards_sub_hints_and_matches_detect_detailed_version() {
    // `detect` is the coarse-bucket API and MUST forward the same
    // VmpVersion that `detect_detailed` returns; regression-catches
    // any future refactor that accidentally drifts the two apart.
    let binary = build_vmp36_binary_with_marker(b"LdrLoadDll\0");
    let (v_coarse, conf_coarse) = VersionDetector::detect(&binary).expect("detect");
    let (detail, conf_detailed) = VersionDetector::detect_detailed(&binary).expect("detect_detailed");
    assert_eq!(v_coarse, detail.version);
    assert_eq!(conf_coarse, conf_detailed);
}

#[test]
fn detector_suppresses_sub_hints_when_version_is_not_3x() {
    // A bare PE lands on VmpVersion::Unknown. Even if the raw bytes
    // happen to contain "LdrLoadDll" (they don't here, but the guard
    // covers the general case), the sub-hint list must stay empty
    // outside the 3.x range so the analyst is not misled.
    use crate::pe_loader::test_util::build_minimal_pe;
    let binary = build_minimal_pe(true, 0x1_4000_0000, 0x1000, &[0x90u8; 32]);
    let (detail, _conf) = VersionDetector::detect_detailed(&binary).expect("detect_detailed");
    assert_eq!(detail.version, VmpVersion::Unknown);
    assert!(
        detail.sub_hints.is_empty(),
        "sub_hints={:?} must be empty for Unknown",
        detail.sub_hints
    );
}

/// Regression for the tiebreaker fix: a `SectionLayout::OneOf` binary
/// (only `.vmp0` present) whose entry stub is `push imm32; call rel32`
/// landing exactly at the start of `.vmp0` scores Vmp2 and Vmp36Plus
/// identically — both 100 points, both with `EntryStub` as their
/// highest-priority rule. Before the fix, `max_by` (forward iteration)
/// resolved this tie to whichever candidate came later in the
/// `candidates` array (Vmp36Plus), regardless of the fact that Vmp2 is
/// the more specific rule (it additionally requires `.vmp0` by name,
/// not just "one of the two"). The fix must deterministically prefer
/// Vmp2.
#[test]
fn detect_breaks_exact_tie_deterministically_toward_vmp2() {
    use crate::pe_loader::test_util::build_minimal_pe_with_named_sections;

    let image_base = 0x1_4000_0000u64;

    // Entry section (RVA 0x1000, per build_minimal_pe_with_named_sections
    // placing the entry point at the first section's RVA): push imm32
    // (dummy 0) followed immediately by call rel32.
    //
    // Second section is laid out right after the first, aligned to
    // 0x1000, so with a ~10-byte first-section body (padded to the
    // 0x200 file-alignment block) the second section lands at RVA
    // 0x2000. The call's rel32 is computed so the branch target is
    // exactly that RVA (start of `.vmp0`).
    let entry_va = image_base + 0x1000;
    let next_instr_va = entry_va + 10; // push(5) + call(5)
    let vmp0_va = image_base + 0x2000;
    let rel32 = (vmp0_va as i64 - next_instr_va as i64) as i32;

    let mut entry_stub = vec![0x68, 0x00, 0x00, 0x00, 0x00]; // push imm32 (dummy)
    entry_stub.push(0xE8); // call rel32
    entry_stub.extend_from_slice(&rel32.to_le_bytes());

    let vmp0_data = [0u8; 16];

    let binary =
        build_minimal_pe_with_named_sections(true, image_base, &[(".text", &entry_stub), (".vmp0", &vmp0_data)]);

    // Sanity check the fixture actually lands where the test assumes,
    // so a future layout change to the builder fails loudly here
    // instead of silently degrading this into a non-tie.
    let sections = binary.get_all_sections().expect("sections");
    assert!(sections.iter().any(|s| s == ".vmp0"), "fixture must have .vmp0");

    let (version, confidence) = VersionDetector::detect(&binary).expect("detect must not error");
    assert_eq!(
        version,
        VmpVersion::Vmp2,
        "exact-tie (100 pts, EntryStub priority) between Vmp2 and Vmp36Plus must resolve to Vmp2"
    );
    assert_eq!(confidence, 100);
}
