//! VMP Version Detection
//!
//! Identifies VMProtect version from binary structure using a scored
//! heuristic rule cascade: entry-stub byte patterns (highest priority),
//! section layout (`.vmp0`/`.vmp1` presence + characteristics), and
//! auxiliary markers (e.g. the literal `"VMProtect"` string).
//!
//! None of the rules are individually certain — VMP's on-disk shape has
//! drifted across releases and public knowledge of it is incomplete — so
//! each rule contributes points to a version candidate and the detector
//! returns both the best-scoring version and a 0-100 confidence value.

use crate::version_matchers::{is_rwx, EntryStubMatcher, PushCallJmpMatch, SectionLayout, SectionLayoutMatcher};
use crate::PEBinary;
use anyhow::{Context, Result};

/// Supported VMP versions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmpVersion {
    /// VMProtect 1.x
    Vmp1,
    /// VMProtect 2.x
    Vmp2,
    /// VMProtect 3.0-3.4
    Vmp30,
    /// VMProtect 3.5.0-3.5.1
    Vmp35,
    /// VMProtect 3.6-3.10.5
    Vmp36Plus,
    /// Unknown version
    Unknown,
}

impl VmpVersion {
    /// Get version string
    pub fn as_str(&self) -> &'static str {
        match self {
            VmpVersion::Vmp1 => "VMP 1.x",
            VmpVersion::Vmp2 => "VMP 2.x",
            VmpVersion::Vmp30 => "VMP 3.0-3.4",
            VmpVersion::Vmp35 => "VMP 3.5.0-3.5.1",
            VmpVersion::Vmp36Plus => "VMP 3.6-3.10.5",
            VmpVersion::Unknown => "Unknown",
        }
    }
}

// ---------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------

/// Rule categories, used to break ties when two version candidates reach
/// the same point total. Higher is stronger evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RulePriority {
    Marker = 1,
    SectionLayout = 2,
    EntryStub = 3,
}

/// Accumulated score for one version candidate.
#[derive(Debug, Default)]
struct RuleScore {
    points: u16,
    top_priority: Option<RulePriority>,
    reasons: Vec<String>,
}

impl RuleScore {
    fn add(&mut self, points: u16, priority: RulePriority, reason: impl Into<String>) {
        self.points = self.points.saturating_add(points);
        self.top_priority = Some(self.top_priority.map_or(priority, |p| p.max(priority)));
        self.reasons.push(reason.into());
    }

    fn confidence(&self) -> u8 {
        self.points.min(100) as u8
    }
}

/// Minimum point total required to accept a candidate as detected;
/// below this the detector reports `Unknown`.
const MIN_CONFIDENCE_THRESHOLD: u16 = 40;
/// Byte window scanned from the entry point when looking for stub patterns.
const ENTRY_SCAN_WINDOW: usize = 32;

/// VMP Version Detector
pub struct VersionDetector;

impl VersionDetector {
    /// Detect VMP version from binary. Returns the best-matching version
    /// along with a 0-100 confidence score.
    pub fn detect(binary: &PEBinary) -> Result<(VmpVersion, u8)> {
        let sections = binary.get_all_sections().context("Failed to enumerate PE sections")?;
        let has_vmp0 = sections.iter().any(|s| s == ".vmp0");
        let has_vmp1 = sections.iter().any(|s| s == ".vmp1");
        let has_text = sections.iter().any(|s| s == ".text");
        let has_rdata = sections.iter().any(|s| s == ".rdata");
        let layout = SectionLayoutMatcher::classify(has_vmp0, has_vmp1);

        let entry_bytes = binary.entry_point_bytes(ENTRY_SCAN_WINDOW).ok();
        let entry_va = binary.entry_point_va().ok();

        let mut vmp1 = RuleScore::default();
        let mut vmp2 = RuleScore::default();
        let mut vmp30 = RuleScore::default();
        let mut vmp35 = RuleScore::default();
        let mut vmp36 = RuleScore::default();

        // --- Section layout rules -----------------------------------
        if layout == SectionLayout::Both {
            vmp35.add(70, RulePriority::SectionLayout, ".vmp0 and .vmp1 both present");
        }
        if layout == SectionLayout::OneOf {
            vmp36.add(50, RulePriority::SectionLayout, "exactly one of .vmp0/.vmp1 present");
            if has_vmp0 {
                vmp2.add(40, RulePriority::SectionLayout, ".vmp0 present, .vmp1 absent");
            }
        }
        if layout == SectionLayout::Neither {
            vmp1.add(20, RulePriority::SectionLayout, "no .vmp0/.vmp1 sections");
            vmp30.add(20, RulePriority::SectionLayout, "no .vmp0/.vmp1 sections");
            if has_text && has_rdata {
                vmp30.add(
                    15,
                    RulePriority::SectionLayout,
                    "standard .text/.rdata sections present",
                );
            }
        }
        if has_text && has_rdata && sections.len() > 5 {
            vmp36.add(10, RulePriority::Marker, "standard sections plus extra section count");
        }

        // --- Entry stub rules ----------------------------------------
        if let Some(bytes) = entry_bytes.as_deref() {
            let vmp1_stub = EntryStubMatcher::find_vmp1_stub(bytes, 16);
            if vmp1_stub.has_pushad && vmp1_stub.has_mov_esi_imm32 {
                vmp1.add(40, RulePriority::EntryStub, "entry stub: pushad + mov esi,imm32");
                if vmp1_stub.has_lea_edi_esi {
                    vmp1.add(10, RulePriority::EntryStub, "entry stub also has lea edi,[esi+disp]");
                }
            }

            if let Some(entry_va) = entry_va {
                if let Some(stub) = EntryStubMatcher::find_push_call_jmp(bytes, ENTRY_SCAN_WINDOW) {
                    let branch = stub.is_call;
                    let target_va = Self::branch_target_va(entry_va, &stub);
                    let target_section = target_va.and_then(|va| Self::section_at_va(binary, va));

                    let kind = if branch { "call" } else { "jmp" };

                    match layout {
                        SectionLayout::Both => {
                            let lands_in_vmp = matches!(target_section.as_deref(), Some(".vmp0") | Some(".vmp1"));
                            if lands_in_vmp {
                                vmp35.add(
                                    25,
                                    RulePriority::EntryStub,
                                    format!("entry stub push+{kind} lands in vmp section"),
                                );
                            }
                        }
                        SectionLayout::OneOf => {
                            let vmp_section_name = if has_vmp0 { ".vmp0" } else { ".vmp1" };
                            let lands_in_vmp = target_section.as_deref() == Some(vmp_section_name);
                            vmp36.add(
                                35,
                                RulePriority::EntryStub,
                                format!("entry stub push+{kind} pattern found"),
                            );
                            if lands_in_vmp {
                                vmp36.add(
                                    15,
                                    RulePriority::EntryStub,
                                    format!("stub target lands in {vmp_section_name}"),
                                );
                                if has_vmp0 {
                                    vmp2.add(30, RulePriority::EntryStub, "entry stub push+call/jmp pattern found");
                                    vmp2.add(30, RulePriority::EntryStub, "stub target lands in .vmp0");
                                }
                            } else if has_vmp0 {
                                vmp2.add(
                                    15,
                                    RulePriority::EntryStub,
                                    "entry stub push+call/jmp pattern found (target unresolved)",
                                );
                            }
                        }
                        SectionLayout::Neither => {
                            vmp30.add(
                                45,
                                RulePriority::EntryStub,
                                format!("entry stub push+{kind} pattern found"),
                            );
                        }
                    }
                }
            }

            // "VMProtect" literal marker (any version)
            if binary.data.windows(9).any(|w| w == b"VMProtect") {
                vmp1.add(15, RulePriority::Marker, "literal \"VMProtect\" string present");
            }

            // API-usage markers — VMP switched from KERNEL32!VirtualProtect
            // to NTDLL!ZwProtectVirtualMemory in the 3.x era. Presence of
            // the Zw* form is a cheap 3.x-vs-2.x discriminator (see
            // RESEARCH_GAPS.md §2.1 and hackyboiz VMP series).
            if binary.data.windows(22).any(|w| w == b"ZwProtectVirtualMemory") {
                vmp30.add(
                    10,
                    RulePriority::Marker,
                    "literal \"ZwProtectVirtualMemory\" (VMP 3.x-era)",
                );
                vmp35.add(
                    10,
                    RulePriority::Marker,
                    "literal \"ZwProtectVirtualMemory\" (VMP 3.x-era)",
                );
                vmp36.add(
                    10,
                    RulePriority::Marker,
                    "literal \"ZwProtectVirtualMemory\" (VMP 3.x-era)",
                );
            }

            // Anti-VM lookup strings that VMProtect ships in its runtime
            // when the "Detect VirtualBox" option is enabled. Confirms
            // ANY VMP version — cheap corroborating evidence.
            if binary.data.windows(7).any(|w| w == b"VBoxRev") || binary.data.windows(7).any(|w| w == b"VBoxVer") {
                vmp1.add(5, RulePriority::Marker, "VBoxRev/VBoxVer anti-VM marker");
                vmp2.add(5, RulePriority::Marker, "VBoxRev/VBoxVer anti-VM marker");
                vmp30.add(5, RulePriority::Marker, "VBoxRev/VBoxVer anti-VM marker");
                vmp35.add(5, RulePriority::Marker, "VBoxRev/VBoxVer anti-VM marker");
                vmp36.add(5, RulePriority::Marker, "VBoxRev/VBoxVer anti-VM marker");
            }
        }

        // Entry-section RWX characteristics (classic VMP1 packer trait)
        if let Some(entry_va) = entry_va {
            if let Some(entry_section) = Self::section_at_va(binary, entry_va) {
                if let Ok(characteristics) = binary.section_characteristics(&entry_section) {
                    if is_rwx(characteristics) {
                        vmp1.add(25, RulePriority::SectionLayout, "entry section is RWX");
                    }
                }
            }
        }

        let candidates = [
            (VmpVersion::Vmp1, vmp1),
            (VmpVersion::Vmp2, vmp2),
            (VmpVersion::Vmp30, vmp30),
            (VmpVersion::Vmp35, vmp35),
            (VmpVersion::Vmp36Plus, vmp36),
        ];

        let best = candidates
            .iter()
            .max_by(|(_, a), (_, b)| a.points.cmp(&b.points).then(a.top_priority.cmp(&b.top_priority)))
            .expect("candidates is non-empty");

        let (version, confidence) = if best.1.points >= MIN_CONFIDENCE_THRESHOLD {
            (best.0, best.1.confidence())
        } else {
            (VmpVersion::Unknown, best.1.confidence())
        };

        if best.1.reasons.is_empty() {
            log::info!(
                "{} detected: no matching heuristics, confidence {}",
                version.as_str(),
                confidence
            );
        } else {
            log::info!(
                "{} detected: {}, confidence {}",
                version.as_str(),
                best.1.reasons.join("; "),
                confidence
            );
        }

        Ok((version, confidence))
    }

    /// Compute the absolute target VA of a `push imm32; call/jmp rel32` stub.
    fn branch_target_va(entry_va: u64, stub: &PushCallJmpMatch) -> Option<u64> {
        let branch_offset = stub.push_offset.checked_add(5)?;
        let next_instr_offset = branch_offset.checked_add(5)?;
        let next_instr_va = entry_va.checked_add(next_instr_offset as u64)?;
        Some((next_instr_va as i64).wrapping_add(stub.rel32 as i64) as u64)
    }

    /// Find the name of the section containing virtual address `va`.
    ///
    /// Uses the `min(virtual_size, size_of_raw_data)` clamp that
    /// [`PEBinary::va_to_offset`] applies, so a bloated `virtual_size`
    /// (attacker-crafted or benignly padded) cannot claim VAs that are
    /// not actually mapped to bytes on disk. Without the clamp the
    /// version detector's "stub lands in .vmpN" rule would fire for a
    /// target VA that other code paths correctly refuse to read.
    fn section_at_va(binary: &PEBinary, va: u64) -> Option<String> {
        let pe = binary.parse_pe().ok()?;
        let image_base = binary.image_base().ok()?;

        for section in &pe.sections {
            let start = image_base.checked_add(section.virtual_address as u64)?;
            let effective_span = (section.virtual_size as u64).min(section.size_of_raw_data as u64);
            let end = start.checked_add(effective_span)?;
            if va >= start && va < end {
                return std::str::from_utf8(&section.name[..])
                    .ok()
                    .map(|s| s.trim_end_matches('\0').to_string());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
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
}
