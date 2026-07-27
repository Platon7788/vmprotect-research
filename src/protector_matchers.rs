//! Vendor byte-pattern tables for [`crate::protector::ProtectorDetector`].
//!
//! Split out of `protector.rs` to keep that file under the crate's 500-line
//! ceiling. Everything here is `pub(crate)` — implementation detail of
//! protector detection, not part of the crate's public API.
//!
//! Pattern data (fingerprint bytes, section-name allowlists) is taken from
//! DiE / PEiD / community writeups — public pattern data, NOT source code
//! copied from GPL-3.0 tools such as vmpattack or NoVmp. See
//! `RESEARCH_GAPS.md` §2.1 for citations.
//!
//! `None` entries in a pattern array denote wildcard bytes, matching
//! [`crate::version_matchers::EntryStubMatcher`]'s convention.

use crate::version_matchers::EntryStubMatcher;

// ---------------------------------------------------------------------
// Themida / WinLicense
// ---------------------------------------------------------------------

/// Themida v1.x compressed entry stub. Layout:
/// `mov eax, imm32` (low 16 bits fixed to 0x0000) + `pushad` + `or eax,eax`
/// + `je +0x58` + `call`. Wildcards on the upper half of the imm32.
pub(crate) const THEMIDA_V1_COMPRESSED_STUB: [Option<u8>; 11] = [
    Some(0xB8),
    Some(0x00),
    Some(0x00),
    None,
    None,
    Some(0x60),
    Some(0x0B),
    Some(0xC0),
    Some(0x74),
    Some(0x58),
    Some(0xE8),
];

/// Themida v1.x uncompressed entry stub:
/// `push ebp; mov ebp,esp; add esp,-0x28; pushad; call 0; pop edx; sub edx,imm`.
/// No wildcards — the whole preamble is verbatim across builds.
pub(crate) const THEMIDA_V1_UNCOMPRESSED_STUB: [Option<u8>; 15] = [
    Some(0x55),
    Some(0x8B),
    Some(0xEC),
    Some(0x83),
    Some(0xC4),
    Some(0xD8),
    Some(0x60),
    Some(0xE8),
    Some(0x00),
    Some(0x00),
    Some(0x00),
    Some(0x00),
    Some(0x5A),
    Some(0x81),
    Some(0xEA),
];

/// Themida DLL v1.8–1.9 entry stub: `mov eax, imm32; pushad; or eax,eax; je +0x68`.
/// Wildcards on the whole imm32 (per-build randomised).
pub(crate) const THEMIDA_DLL_STUB: [Option<u8>; 10] = [
    Some(0xB8),
    None,
    None,
    None,
    None,
    Some(0x60),
    Some(0x0B),
    Some(0xC0),
    Some(0x74),
    Some(0x68),
];

/// Themida / WinLicense section-name allowlist. The two trailing entries —
/// three spaces and eight spaces — are Themida 2.1.x / 3.0.x per-build
/// randomised names that happen to be all whitespace and are unique enough
/// on their own to signal Themida.
pub(crate) const THEMIDA_SECTION_NAMES: &[&str] = &[
    "Themida", ".Themida", ".themida", "WinLicen", ".winlice", "   ", "        ",
];

/// Themida / WinLicense string markers scanned across the whole file image.
pub(crate) const THEMIDA_STRING_MARKERS: &[&[u8]] = &[b"Themida", b"WinLicense", b"Oreans"];

// ---------------------------------------------------------------------
// Enigma Protector
// ---------------------------------------------------------------------

/// Enigma Protector entry stub: `pushad; call 0; pop ebp; mov edx,ebp; sub ebp,imm`.
pub(crate) const ENIGMA_STUB: [Option<u8>; 11] = [
    Some(0x60),
    Some(0xE8),
    Some(0x00),
    Some(0x00),
    Some(0x00),
    Some(0x00),
    Some(0x5D),
    Some(0x8B),
    Some(0xD5),
    Some(0x81),
    Some(0xED),
];

/// Enigma section-name allowlist.
pub(crate) const ENIGMA_SECTION_NAMES: &[&str] = &[".enigma0", ".enigma1", ".enigma2", ".enigma3"];

/// Enigma string markers scanned across the whole file image.
pub(crate) const ENIGMA_STRING_MARKERS: &[&[u8]] = &[b"Enigma protector v", b"ENIGMA", b"P.rel$oc$"];

// ---------------------------------------------------------------------
// Obsidium
// ---------------------------------------------------------------------

/// Obsidium anti-disassembly short-jump entry stub:
/// `jmp +3` (over 3 junk bytes) + `call rel32` + `pop eax`.
pub(crate) const OBSIDIUM_STUB: [Option<u8>; 11] = [
    Some(0xEB),
    Some(0x03),
    None,
    None,
    None,
    Some(0xE8),
    None,
    None,
    None,
    None,
    Some(0x58),
];

// ---------------------------------------------------------------------
// Armadillo / SoftwarePassport
// ---------------------------------------------------------------------

/// Armadillo entry stub: `pushad; call 0; pop ebp; sub ebp,imm`.
pub(crate) const ARMADILLO_STUB: [Option<u8>; 9] = [
    Some(0x60),
    Some(0xE8),
    Some(0x00),
    Some(0x00),
    Some(0x00),
    Some(0x00),
    Some(0x5D),
    Some(0x81),
    Some(0xED),
];

/// Armadillo section-name allowlist. Note that `.pdata` collides with the
/// real x64 unwind-info section — the protector rule REQUIRES at least
/// two of these names to co-occur before firing.
pub(crate) const ARMADILLO_SECTION_NAMES: &[&str] = &[".text1", ".adata", ".data1", ".pdata"];

// ---------------------------------------------------------------------
// ASPack / ASProtect
// ---------------------------------------------------------------------

/// ASPack entry stub:
/// `pushad; call +3; jmp $+9; jmp +4; pop ebp; inc ebp; push ebp; ret`.
pub(crate) const ASPACK_STUB: [Option<u8>; 13] = [
    Some(0x60),
    Some(0xE8),
    Some(0x03),
    Some(0x00),
    Some(0x00),
    Some(0x00),
    Some(0xE9),
    Some(0xEB),
    Some(0x04),
    Some(0x5D),
    Some(0x45),
    Some(0x55),
    Some(0xC3),
];

/// ASPack / ASProtect section-name allowlist. `.adata` is shared with
/// Armadillo — the disambiguation is done by scoring (ASPack fires on any
/// single hit while Armadillo requires two).
pub(crate) const ASPACK_SECTION_NAMES: &[&str] = &[".aspack", "ASPack", ".ASPack", ".adata"];

// ---------------------------------------------------------------------
// Code Virtualizer (Oreans, standalone)
// ---------------------------------------------------------------------

/// Code Virtualizer central dispatcher: `lodsb; movzx eax,al; jmp [edi+eax*4]`.
/// A 7-byte fingerprint specific enough that a whole-file scan is safe from
/// false positives.
pub(crate) const CODE_VIRTUALIZER_DISPATCHER: [Option<u8>; 7] = [
    Some(0xAC),
    Some(0x0F),
    Some(0xB6),
    Some(0xC0),
    Some(0xFF),
    Some(0x24),
    Some(0x87),
];

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Scan the first `scan_window` bytes of `data` for `pattern`, returning
/// `true` if any offset matches. Thin wrapper around
/// [`EntryStubMatcher::find`] so vendor-scoring code can express the intent
/// ("does the file contain this fingerprint anywhere") without hard-coding
/// `.is_some()` at every call site.
pub(crate) fn contains_pattern(data: &[u8], pattern: &[Option<u8>], scan_window: usize) -> bool {
    EntryStubMatcher::find(data, pattern, scan_window).is_some()
}

/// True when `haystack` contains `needle` anywhere. The `.windows` iterator
/// short-circuits on the first match. Kept as a helper to avoid the awkward
/// `data.windows(needle.len()).any(|w| w == needle)` idiom repeating for
/// every vendor string marker.
pub(crate) fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
