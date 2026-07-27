//! Protector-family detection layer.
//!
//! Sits BEFORE `VmpDevirtualizer` in the analysis pipeline: identifies
//! which packer / protector (if any) processed the binary. Only when the
//! family is [`ProtectorFamily::VmProtect`] does the VMP-specific version
//! detector + dispatch-table extractor make sense to run; other families
//! either need a different toolchain (Themida, Denuvo, ...) or nothing at
//! all (unpacked binaries).
//!
//! Design mirrors [`crate::version::VersionDetector`]: each candidate
//! family accumulates points from a set of independent rules, and the
//! best-scoring candidate above a minimum threshold wins. Below the
//! threshold the report falls back to either
//! [`ProtectorFamily::UnknownProtector`] (class-level obfuscation signals
//! fired without a vendor hit) or [`ProtectorFamily::Unprotected`] (no
//! signals at all).
//!
//! Coverage in this initial module is intentionally narrow — VMProtect,
//! the five common file-compressor families, and the class-level
//! catch-all. Per-vendor byte-table matchers for Themida, Enigma,
//! Obsidium, Armadillo, ASPack, Code Virtualizer, and friends are the
//! task of the follow-up (see `RESEARCH_GAPS.md` §2.1 and §2.2).

use crate::PEBinary;
use anyhow::{Context, Result};

/// Windows PE protector / packer families this tool is aware of.
///
/// Variants named after the vendor's product where possible. Sub-versions
/// (e.g. VMProtect 1.x vs 3.x) are discriminated further by
/// [`crate::VersionDetector`] once the family is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ProtectorFamily {
    // VM-based protectors
    /// VMProtect (VMPSoft). Family confirmation; use `VersionDetector` for
    /// the 1.x / 2.x / 3.x split.
    VmProtect,
    /// Themida / WinLicense (Oreans). Placeholder — byte-table matchers
    /// arrive in the follow-up commit.
    Themida,
    /// Code Virtualizer (Oreans, standalone product). Placeholder.
    CodeVirtualizer,
    /// Enigma Protector. Placeholder.
    EnigmaProtector,
    /// Obsidium. Placeholder.
    Obsidium,
    /// Armadillo / SoftwarePassport. Placeholder.
    Armadillo,
    /// ASPack / ASProtect. Placeholder.
    AsPack,
    /// ExeCryptor (SoftComplete, legacy). Placeholder.
    ExeCryptor,
    /// SafEngine Shielden. Placeholder.
    SafEngine,
    /// Denuvo Anti-Tamper. Custom `.vm` stack machine — this tool
    /// deliberately refuses (see `RESEARCH_GAPS.md` §1). Placeholder.
    Denuvo,

    // Compressors (short-circuit "packed but not virtualised")
    /// UPX and forks.
    Upx,
    /// MPRESS.
    Mpress,
    /// Petite.
    Petite,
    /// PECompact.
    PeCompact,
    /// Upack.
    Upack,

    // Catch-alls
    /// Some obfuscation signals fired (entropy, W+X, stripped IAT,
    /// entry point outside `.text`, ...) but no known vendor matched.
    UnknownProtector,
    /// No obfuscation signals at all — likely a normal PE.
    Unprotected,
}

impl ProtectorFamily {
    /// Human-readable name for the family.
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtectorFamily::VmProtect => "VMProtect",
            ProtectorFamily::Themida => "Themida / WinLicense",
            ProtectorFamily::CodeVirtualizer => "Code Virtualizer",
            ProtectorFamily::EnigmaProtector => "Enigma Protector",
            ProtectorFamily::Obsidium => "Obsidium",
            ProtectorFamily::Armadillo => "Armadillo / SoftwarePassport",
            ProtectorFamily::AsPack => "ASPack / ASProtect",
            ProtectorFamily::ExeCryptor => "ExeCryptor",
            ProtectorFamily::SafEngine => "SafEngine Shielden",
            ProtectorFamily::Denuvo => "Denuvo Anti-Tamper",
            ProtectorFamily::Upx => "UPX",
            ProtectorFamily::Mpress => "MPRESS",
            ProtectorFamily::Petite => "Petite",
            ProtectorFamily::PeCompact => "PECompact",
            ProtectorFamily::Upack => "Upack",
            ProtectorFamily::UnknownProtector => "Unknown protector",
            ProtectorFamily::Unprotected => "Unprotected",
        }
    }

    /// True when this family is a VM-based protector — worth trying to
    /// devirtualise. Compressors and `Unprotected` return `false`.
    pub fn is_vm_protector(&self) -> bool {
        matches!(
            self,
            ProtectorFamily::VmProtect
                | ProtectorFamily::Themida
                | ProtectorFamily::CodeVirtualizer
                | ProtectorFamily::EnigmaProtector
                | ProtectorFamily::Obsidium
                | ProtectorFamily::Armadillo
                | ProtectorFamily::AsPack
                | ProtectorFamily::ExeCryptor
                | ProtectorFamily::SafEngine
                | ProtectorFamily::Denuvo
        )
    }

    /// True when this tool has actual devirtualisation support for the
    /// family (as opposed to detection only). Currently only VMProtect.
    pub fn is_supported_for_devirt(&self) -> bool {
        matches!(self, ProtectorFamily::VmProtect)
    }
}

/// Detection report: the winning family, a 0-100 confidence, and a list
/// of the rules that fired (for logging / --verbose).
#[derive(Debug, Clone)]
pub struct ProtectorReport {
    /// Best-matching family.
    pub family: ProtectorFamily,
    /// 0-100 confidence, matching [`crate::VersionDetector`]'s scale.
    pub confidence: u8,
    /// One string per rule that contributed points, in insertion order.
    pub reasons: Vec<String>,
}

/// Accumulator for one candidate family — mirrors
/// [`crate::version`]'s private `RuleScore` shape but public here because
/// [`ProtectorDetector`] returns multiple candidates from the same scan.
#[derive(Debug, Default)]
struct FamilyScore {
    points: u16,
    reasons: Vec<String>,
}

impl FamilyScore {
    fn add(&mut self, points: u16, reason: impl Into<String>) {
        self.points = self.points.saturating_add(points);
        self.reasons.push(reason.into());
    }

    fn confidence(&self) -> u8 {
        self.points.min(100) as u8
    }
}

/// Minimum point total for a vendor-specific verdict to override the
/// `UnknownProtector` / `Unprotected` fallback.
const MIN_VENDOR_CONFIDENCE: u16 = 40;

/// Minimum point total for `UnknownProtector` to override `Unprotected`.
const MIN_UNKNOWN_CONFIDENCE: u16 = 30;

/// PE `Characteristics` bit for executable code.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// PE `Characteristics` bit for writable memory.
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Threshold above which a section's Shannon entropy counts as
/// "packed/encrypted" (bits per byte). 7.0 is the widely-used cut-off,
/// e.g. Detect It Easy, REMINDer, PE-LiteScan.
const ENTROPY_THRESHOLD: f64 = 7.0;

/// Maximum number of PE imports considered a "stripped IAT" — every
/// remaining import is usually just `LoadLibraryA` / `GetProcAddress` /
/// `VirtualProtect` / `VirtualAlloc` / `ExitProcess` and cousins.
const STRIPPED_IAT_MAX: usize = 12;

/// Protector-family detector.
pub struct ProtectorDetector;

impl ProtectorDetector {
    /// Run every family rule against `binary` and return the winning
    /// verdict.
    pub fn detect(binary: &PEBinary) -> Result<ProtectorReport> {
        let sections = binary.get_all_sections().context("enumerate PE sections")?;

        let mut vmprotect = FamilyScore::default();
        let mut upx = FamilyScore::default();
        let mut mpress = FamilyScore::default();
        let mut petite = FamilyScore::default();
        let mut pecompact = FamilyScore::default();
        let mut upack = FamilyScore::default();
        let mut unknown = FamilyScore::default();

        // --- Vendor: VMProtect (section names + literal marker) ------
        //
        // Only the strongest section-name signals here — the full VMP
        // discrimination between 1.x/2.x/3.x lives in `version.rs`. We
        // just need enough confidence to route the CLI to
        // `VmpDevirtualizer`.
        let has_vmp0 = sections.iter().any(|s| s == ".vmp0");
        let has_vmp1 = sections.iter().any(|s| s == ".vmp1");
        if has_vmp0 && has_vmp1 {
            vmprotect.add(70, "`.vmp0` and `.vmp1` sections both present");
        } else if has_vmp0 || has_vmp1 {
            vmprotect.add(50, "one of `.vmp0`/`.vmp1` present");
        }
        if binary.data.windows(9).any(|w| w == b"VMProtect") {
            vmprotect.add(15, "literal \"VMProtect\" string");
        }
        // ZwProtectVirtualMemory tends to be a 3.x-era API rather than
        // 2.x's VirtualProtect — cheap version-side signal that also
        // confirms VMProtect at the family layer.
        if binary.data.windows(22).any(|w| w == b"ZwProtectVirtualMemory") {
            vmprotect.add(15, "literal \"ZwProtectVirtualMemory\" string (VMP 3.x-era)");
        }

        // --- Compressors (section-name allowlist) --------------------
        if sections.iter().any(|s| s == "UPX0" || s == "UPX1" || s == "UPX2") {
            upx.add(80, "one of `UPX0`/`UPX1`/`UPX2` sections present");
        }
        if sections.iter().any(|s| s == ".MPRESS1" || s == ".MPRESS2") {
            mpress.add(80, "one of `.MPRESS1`/`.MPRESS2` sections present");
        }
        if sections.iter().any(|s| s == ".petite") {
            petite.add(80, "`.petite` section present");
        }
        if sections
            .iter()
            .any(|s| s == "PEC2TO" || s == "PEC2" || s == "PEC2MO" || s.starts_with("pec"))
        {
            pecompact.add(70, "PECompact section prefix present");
        }
        if sections.iter().any(|s| s == ".Upack" || s == ".ByDwing") {
            upack.add(80, "one of `.Upack`/`.ByDwing` sections present");
        }

        // --- Class-level obfuscation signals (feed `unknown`) --------
        //
        // These are per-signal weak; the aggregator has to see two or
        // three fire before it clears `MIN_UNKNOWN_CONFIDENCE`. This
        // prevents a well-behaved binary that happens to have one W+X
        // section (unusual but not unheard of) from being labelled
        // "protector" on that alone.
        if Self::has_wx_section(binary).unwrap_or(false) {
            unknown.add(20, "at least one W+X section (writable + executable)");
        }
        if let Ok(entries) = Self::high_entropy_sections(binary) {
            if !entries.is_empty() {
                let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
                unknown.add(15, format!("high-entropy sections (> {ENTROPY_THRESHOLD}): {names:?}"));
            }
        }
        if Self::import_count(binary)
            .map(|c| c <= STRIPPED_IAT_MAX)
            .unwrap_or(false)
        {
            unknown.add(15, format!("stripped IAT (<= {STRIPPED_IAT_MAX} imports)"));
        }
        if Self::entry_point_outside_text(binary).unwrap_or(false) {
            unknown.add(20, "entry point falls outside `.text`");
        }

        // --- Pick winner ---------------------------------------------
        let vendor_candidates = [
            (ProtectorFamily::VmProtect, vmprotect),
            (ProtectorFamily::Upx, upx),
            (ProtectorFamily::Mpress, mpress),
            (ProtectorFamily::Petite, petite),
            (ProtectorFamily::PeCompact, pecompact),
            (ProtectorFamily::Upack, upack),
        ];

        let best_vendor = vendor_candidates
            .iter()
            .max_by_key(|(_, s)| s.points)
            .expect("candidate list is non-empty");

        let (family, score) = if best_vendor.1.points >= MIN_VENDOR_CONFIDENCE {
            (best_vendor.0, &best_vendor.1)
        } else if unknown.points >= MIN_UNKNOWN_CONFIDENCE {
            (ProtectorFamily::UnknownProtector, &unknown)
        } else {
            (ProtectorFamily::Unprotected, &unknown)
        };

        let report = ProtectorReport {
            family,
            confidence: score.confidence(),
            reasons: score.reasons.clone(),
        };

        log::info!(
            "protector family: {} @ {}/100 ({} reasons)",
            report.family.as_str(),
            report.confidence,
            report.reasons.len()
        );

        Ok(report)
    }

    /// True when any section has both `MEM_EXECUTE` and `MEM_WRITE` set.
    fn has_wx_section(binary: &PEBinary) -> Result<bool> {
        let names = binary.get_all_sections()?;
        for name in names {
            if let Ok(ch) = binary.section_characteristics(&name) {
                if (ch & IMAGE_SCN_MEM_EXECUTE) != 0 && (ch & IMAGE_SCN_MEM_WRITE) != 0 {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Sections whose Shannon entropy exceeds [`ENTROPY_THRESHOLD`],
    /// excluding `.rsrc` (resources are naturally high-entropy: PNG,
    /// compressed strings, digital signatures).
    fn high_entropy_sections(binary: &PEBinary) -> Result<Vec<(String, f64)>> {
        let names = binary.get_all_sections()?;
        let mut hits = Vec::new();
        for name in names {
            if name == ".rsrc" {
                continue;
            }
            let data = match binary.get_section(&name) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if data.len() < 256 {
                continue;
            }
            let ent = shannon_entropy(&data);
            if ent > ENTROPY_THRESHOLD {
                hits.push((name, ent));
            }
        }
        Ok(hits)
    }

    /// Count of resolved imports across all import descriptors.
    fn import_count(binary: &PEBinary) -> Result<usize> {
        let pe = binary.parse_pe()?;
        Ok(pe.imports.len())
    }

    /// True when the entry-point VA does NOT fall inside a section named
    /// `.text`. Bootstrap stubs in a packer section satisfy this.
    fn entry_point_outside_text(binary: &PEBinary) -> Result<bool> {
        let entry_va = binary.entry_point_va()?;
        let pe = binary.parse_pe()?;
        let image_base = binary.image_base()?;
        for section in &pe.sections {
            let start = image_base.saturating_add(section.virtual_address as u64);
            let effective = (section.virtual_size as u64).min(section.size_of_raw_data as u64);
            let end = start.saturating_add(effective);
            if entry_va >= start && entry_va < end {
                let name = std::str::from_utf8(&section.name[..])
                    .unwrap_or("")
                    .trim_end_matches('\0');
                return Ok(name != ".text");
            }
        }
        // Entry VA lands in no section at all — very unusual, treat as suspicious.
        Ok(true)
    }
}

/// Shannon entropy of a byte slice, in bits per byte (0.0 – 8.0).
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// Count byte-frequency histogram once for cheap tests to inspect
/// entropy computations without duplicating the logic.
#[cfg(test)]
pub(crate) fn shannon_entropy_for_tests(data: &[u8]) -> f64 {
    shannon_entropy(data)
}

#[cfg(test)]
#[path = "protector_tests.rs"]
mod tests;

/// Helper used by [`ProtectorFamily::as_str`] callers that need a stable
/// key (e.g. JSON export). Same string as `as_str`.
///
/// Kept as a free function so `ProtectorFamily`'s `Display` impl stays
/// clean of tokenisation concerns.
pub fn family_key(family: ProtectorFamily) -> &'static str {
    family.as_str()
}
