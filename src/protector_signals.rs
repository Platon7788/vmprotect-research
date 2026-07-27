//! Class-level obfuscation signals used by [`crate::protector::ProtectorDetector`].
//!
//! Split from `protector.rs` to keep that file under the crate's 500-line
//! ceiling once the per-vendor byte-table matchers landed in Commit F.
//! Everything here is `pub(crate)` — implementation detail of protector
//! detection, not part of the crate's public API.

use crate::PEBinary;
use anyhow::Result;

/// PE `Characteristics` bit for executable code.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// PE `Characteristics` bit for writable memory.
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Threshold above which a section's Shannon entropy counts as
/// "packed/encrypted" (bits per byte). 7.0 is the widely-used cut-off,
/// e.g. Detect It Easy, REMINDer, PE-LiteScan.
pub(crate) const ENTROPY_THRESHOLD: f64 = 7.0;

/// Maximum number of PE imports considered a "stripped IAT" — every
/// remaining import is usually just `LoadLibraryA` / `GetProcAddress` /
/// `VirtualProtect` / `VirtualAlloc` / `ExitProcess` and cousins.
pub(crate) const STRIPPED_IAT_MAX: usize = 12;

/// True when any section has both `MEM_EXECUTE` and `MEM_WRITE` set.
pub(crate) fn has_wx_section(binary: &PEBinary) -> Result<bool> {
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
pub(crate) fn high_entropy_sections(binary: &PEBinary) -> Result<Vec<(String, f64)>> {
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
pub(crate) fn import_count(binary: &PEBinary) -> Result<usize> {
    let pe = binary.parse_pe()?;
    Ok(pe.imports.len())
}

/// True when the entry-point VA does NOT fall inside a section named
/// `.text`. Bootstrap stubs in a packer section satisfy this.
pub(crate) fn entry_point_outside_text(binary: &PEBinary) -> Result<bool> {
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

/// Shannon entropy of a byte slice, in bits per byte (0.0 – 8.0).
pub(crate) fn shannon_entropy(data: &[u8]) -> f64 {
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
