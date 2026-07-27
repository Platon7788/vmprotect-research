//! Class-level obfuscation signals used by [`crate::protector::ProtectorDetector`].
//!
//! Split from `protector.rs` to keep that file under the crate's 500-line
//! ceiling once the per-vendor byte-table matchers landed in Commit F.
//! Everything here is `pub(crate)` — implementation detail of protector
//! detection, not part of the crate's public API.

use crate::protector_matchers::{has_add_reg_mem, has_indirect_jmp_ff4, has_mov_indirect_load, has_xor_reg_imm};
use crate::PEBinary;
use anyhow::Result;

/// PE `Characteristics` bit for executable code.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// PE `Characteristics` bit for writable memory.
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Sliding-window size for the structural dispatcher scan (Commit I). Per
/// `RESEARCH_GAPS.md` §4.1, VMP's `mov/xor/add/jmp` chain can have up to
/// ~16 bytes of junk between each step; 64 bytes covers that gap plus the
/// four primitives' own encoded length (2-7 bytes each) with headroom.
const DISPATCHER_WINDOW: usize = 64;

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

/// Scan every section with `IMAGE_SCN_MEM_EXECUTE` set for VMProtect's
/// central dispatcher shape: `mov reg,[vip]` / `xor reg,imm` / `add
/// reg,[table]` / `jmp [reg]` co-occurring within a
/// [`DISPATCHER_WINDOW`]-byte sliding window. The first three may appear
/// in any order (VMP randomises it per build) -- this only checks that
/// all four shapes exist somewhere in the same window, not a fixed
/// sequence. Returns on the first hit; the section name and offset are
/// logged so a `--verbose` run can show where the fingerprint sat.
///
/// This is byte-pattern-only (no disassembly), so it carries some
/// false-positive risk on non-VMP code that happens to contain all four
/// shapes within 64 bytes. That risk is accepted here because the caller
/// only spends 45 of the 100 confidence points on it -- see
/// `RESEARCH_GAPS.md` §2.3 for the rationale and the BattlEye/EAC/renamed-
/// section use case this exists for.
pub(crate) fn scan_rx_sections_for_dispatcher(binary: &PEBinary) -> Result<bool> {
    let names = binary.get_all_sections()?;
    for name in names {
        let characteristics = match binary.section_characteristics(&name) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }
        let data = match binary.get_section(&name) {
            Ok(d) => d,
            Err(_) => continue,
        };
        if data.len() < DISPATCHER_WINDOW {
            continue;
        }
        let max_offset = data.len() - DISPATCHER_WINDOW;
        for offset in 0..=max_offset {
            let window = &data[offset..offset + DISPATCHER_WINDOW];
            if has_mov_indirect_load(window)
                && has_xor_reg_imm(window)
                && has_add_reg_mem(window)
                && has_indirect_jmp_ff4(window)
            {
                // Sanitise the attacker-influenced section name before
                // it hits the log line — a crafted PE can name a section
                // `.vmp0\x1B[31m` and inject ANSI escapes / CR-LF into
                // the analyst's terminal under `--verbose`. Commit J's
                // sanitiser sweep predated this call site (added by I);
                // covered here in the T fix.
                let safe_name = crate::pe_loader::sanitise_section_name(&name);
                log::debug!("structural VMP dispatcher fingerprint found in section `{safe_name}` at offset 0x{offset:x}");
                return Ok(true);
            }
        }
    }
    Ok(false)
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

#[cfg(test)]
#[path = "protector_signals_tests.rs"]
mod tests;
