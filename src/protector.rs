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
//! Coverage now includes VMProtect, seven VM-based protector vendors
//! (Themida/WinLicense, Code Virtualizer, Enigma, Obsidium, Armadillo,
//! ASPack/ASProtect, Denuvo), the five common file-compressor families,
//! two special-cased VMP-wrappers (BattlEye BEDaisy → VmProtect,
//! Vanguard/Packman → UnknownProtector), and the class-level catch-all.
//! Per-vendor byte-pattern data lives in `protector_matchers.rs` — see
//! `RESEARCH_GAPS.md` §2.1 for the citations behind each fingerprint.

use crate::protector_matchers::{
    contains_bytes, contains_pattern, ARMADILLO_SECTION_NAMES, ARMADILLO_STUB, ASPACK_SECTION_NAMES, ASPACK_STUB,
    CODE_VIRTUALIZER_DISPATCHER, ENIGMA_SECTION_NAMES, ENIGMA_STRING_MARKERS, ENIGMA_STUB, OBSIDIUM_STUB,
    THEMIDA_DLL_STUB, THEMIDA_SECTION_NAMES, THEMIDA_STRING_MARKERS, THEMIDA_V1_COMPRESSED_STUB,
    THEMIDA_V1_UNCOMPRESSED_STUB,
};
use crate::protector_signals as signals;
use crate::version_matchers::EntryStubMatcher;
use crate::PEBinary;
use anyhow::{Context, Result};

/// Byte window scanned from the entry point when looking for vendor stubs.
/// Same size as the version detector's window — small enough that a wrong
/// entry section (bare fixture with `.test`) still bounds the read.
const ENTRY_SCAN_WINDOW: usize = 64;

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

/// Protector-family detector.
pub struct ProtectorDetector;

impl ProtectorDetector {
    /// Run every family rule against `binary` and return the winning
    /// verdict.
    pub fn detect(binary: &PEBinary) -> Result<ProtectorReport> {
        let sections = binary.get_all_sections().context("enumerate PE sections")?;

        let mut vmprotect = FamilyScore::default();
        let mut themida = FamilyScore::default();
        let mut code_virtualizer = FamilyScore::default();
        let mut enigma = FamilyScore::default();
        let mut obsidium = FamilyScore::default();
        let mut armadillo = FamilyScore::default();
        let mut aspack = FamilyScore::default();
        let mut denuvo = FamilyScore::default();
        let mut upx = FamilyScore::default();
        let mut mpress = FamilyScore::default();
        let mut petite = FamilyScore::default();
        let mut pecompact = FamilyScore::default();
        let mut upack = FamilyScore::default();
        let mut unknown = FamilyScore::default();

        // Entry-point bytes borrowed for every vendor's stub matcher below.
        // `ok()` swallows a header-parse error — a truly malformed PE just
        // means no stub rules fire, which is the correct fallback.
        let entry_bytes = binary.entry_point_bytes(ENTRY_SCAN_WINDOW).ok();

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
        if contains_bytes(&binary.data, b"VMProtect") {
            vmprotect.add(15, "literal \"VMProtect\" string");
        }
        // ZwProtectVirtualMemory tends to be a 3.x-era API rather than
        // 2.x's VirtualProtect — cheap version-side signal that also
        // confirms VMProtect at the family layer.
        if contains_bytes(&binary.data, b"ZwProtectVirtualMemory") {
            vmprotect.add(15, "literal \"ZwProtectVirtualMemory\" string (VMP 3.x-era)");
        }

        // --- Vendor: Themida / WinLicense ----------------------------
        for &name in THEMIDA_SECTION_NAMES {
            if sections.iter().any(|s| s == name) {
                themida.add(40, format!("Themida section name `{name}`"));
            }
        }
        for &marker in THEMIDA_STRING_MARKERS {
            if contains_bytes(&binary.data, marker) {
                themida.add(15, format!("literal \"{}\" string", String::from_utf8_lossy(marker)));
            }
        }
        if let Some(bytes) = entry_bytes.as_deref() {
            if EntryStubMatcher::matches(bytes, &THEMIDA_V1_COMPRESSED_STUB) {
                themida.add(40, "Themida v1.x compressed entry stub");
            }
            if EntryStubMatcher::matches(bytes, &THEMIDA_V1_UNCOMPRESSED_STUB) {
                themida.add(40, "Themida v1.x uncompressed entry stub");
            }
            if EntryStubMatcher::matches(bytes, &THEMIDA_DLL_STUB) {
                themida.add(30, "Themida DLL v1.8-1.9 entry stub");
            }
        }

        // --- Vendor: Enigma Protector --------------------------------
        for &name in ENIGMA_SECTION_NAMES {
            if sections.iter().any(|s| s == name) {
                enigma.add(50, format!("Enigma section name `{name}`"));
            }
        }
        for &marker in ENIGMA_STRING_MARKERS {
            if contains_bytes(&binary.data, marker) {
                enigma.add(15, format!("literal \"{}\" string", String::from_utf8_lossy(marker)));
            }
        }
        if let Some(bytes) = entry_bytes.as_deref() {
            if EntryStubMatcher::matches(bytes, &ENIGMA_STUB) {
                enigma.add(40, "Enigma entry-stub prelude");
            }
        }

        // --- Vendor: Obsidium ----------------------------------------
        if let Some(bytes) = entry_bytes.as_deref() {
            if EntryStubMatcher::matches(bytes, &OBSIDIUM_STUB) {
                obsidium.add(50, "Obsidium short-jump anti-disasm entry stub");
            }
        }

        // --- Vendor: Armadillo / SoftwarePassport --------------------
        //
        // `.pdata` collides with the real x64 unwind-info section, so
        // require at least TWO section-name hits before firing. This
        // deliberately trades recall for precision on well-behaved x64
        // binaries that happen to have `.pdata`.
        let armadillo_section_hits = ARMADILLO_SECTION_NAMES
            .iter()
            .filter(|&&name| sections.iter().any(|s| s == name))
            .count();
        if armadillo_section_hits >= 2 {
            let matched: Vec<&str> = ARMADILLO_SECTION_NAMES
                .iter()
                .copied()
                .filter(|&name| sections.iter().any(|s| s == name))
                .collect();
            armadillo.add(45, format!("Armadillo section names present: {matched:?}"));
        }
        if let Some(bytes) = entry_bytes.as_deref() {
            if EntryStubMatcher::matches(bytes, &ARMADILLO_STUB) {
                armadillo.add(40, "Armadillo entry-stub prelude");
            }
        }
        if contains_bytes(&binary.data, b"CopyMemII") {
            armadillo.add(25, "literal \"CopyMemII\" string");
        }

        // --- Vendor: ASPack / ASProtect ------------------------------
        for &name in ASPACK_SECTION_NAMES {
            if sections.iter().any(|s| s == name) {
                aspack.add(50, format!("ASPack section name `{name}`"));
            }
        }
        if let Some(bytes) = entry_bytes.as_deref() {
            if EntryStubMatcher::matches(bytes, &ASPACK_STUB) {
                aspack.add(40, "ASPack entry-stub prelude");
            }
        }

        // --- Vendor: Code Virtualizer (Oreans standalone) ------------
        //
        // The 7-byte dispatcher fingerprint is specific enough for a
        // whole-file scan to be false-positive-safe. Scanning `binary.data`
        // rather than per-section keeps the code short and picks up
        // dispatchers in obfuscator-renamed code sections.
        if contains_pattern(&binary.data, &CODE_VIRTUALIZER_DISPATCHER, binary.data.len()) {
            code_virtualizer.add(60, "Code Virtualizer dispatcher fingerprint (AC 0F B6 C0 FF 24 87)");
        }

        // --- Vendor: Denuvo Anti-Tamper (detect and refuse) ----------
        //
        // Section literally named `.vm` is the classic Denuvo marker.
        // Roughly 30% false positive rate against benign binaries, which
        // is acceptable given Denuvo's ubiquity in commercial games.
        if sections.iter().any(|s| s == ".vm") {
            denuvo.add(60, "Denuvo `.vm` section (case-sensitive)");
        }

        // --- BattlEye BEDaisy (VMP wrapper with scrubbed sections) ---
        //
        // BattlEye rewraps VMProtect with a scrubbed section name. The
        // structural VMP-3 matchers would fire on real code but our
        // section-name gate misses it, so `.be0` bumps VmProtect
        // directly and lets `VmpDevirtualizer` take over.
        if sections.iter().any(|s| s == ".be0") {
            vmprotect.add(60, "BattlEye BEDaisy `.be0` section (VMP-family shell)");
        }

        // --- Vanguard stub.dll (Packman shell) -----------------------
        //
        // Packman isn't in the ProtectorFamily enum. Feed
        // `UnknownProtector` with a specific reason string so operators
        // can spot the Riot Vanguard wrapper without scrolling through
        // the class-level signals.
        let stub_count = sections.iter().filter(|s| *s == ".stub").count();
        if stub_count >= 2 {
            unknown.add(30, "Vanguard/Packman shell (.stub x2)");
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
        if signals::has_wx_section(binary).unwrap_or(false) {
            unknown.add(20, "at least one W+X section (writable + executable)");
        }
        if let Ok(entries) = signals::high_entropy_sections(binary) {
            if !entries.is_empty() {
                let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
                unknown.add(
                    15,
                    format!("high-entropy sections (> {}): {names:?}", signals::ENTROPY_THRESHOLD),
                );
            }
        }
        if signals::import_count(binary)
            .map(|c| c <= signals::STRIPPED_IAT_MAX)
            .unwrap_or(false)
        {
            unknown.add(15, format!("stripped IAT (<= {} imports)", signals::STRIPPED_IAT_MAX));
        }
        if signals::entry_point_outside_text(binary).unwrap_or(false) {
            unknown.add(20, "entry point falls outside `.text`");
        }

        // --- Pick winner ---------------------------------------------
        let vendor_candidates = [
            (ProtectorFamily::VmProtect, vmprotect),
            (ProtectorFamily::Themida, themida),
            (ProtectorFamily::CodeVirtualizer, code_virtualizer),
            (ProtectorFamily::EnigmaProtector, enigma),
            (ProtectorFamily::Obsidium, obsidium),
            (ProtectorFamily::Armadillo, armadillo),
            (ProtectorFamily::AsPack, aspack),
            (ProtectorFamily::Denuvo, denuvo),
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
}

/// Count byte-frequency histogram once for cheap tests to inspect
/// entropy computations without duplicating the logic.
#[cfg(test)]
pub(crate) fn shannon_entropy_for_tests(data: &[u8]) -> f64 {
    signals::shannon_entropy(data)
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
