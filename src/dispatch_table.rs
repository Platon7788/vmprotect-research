//! Dispatch Table Locator
//!
//! Finds and extracts VMP dispatch table from binary.

use crate::{DispatchExtractorPy, PEBinary, XorKeyAnalyzer};
use anyhow::Result;

/// Dispatch table locator
pub struct DispatchTableLocator;

impl DispatchTableLocator {
    /// Locate dispatch table VA in binary.
    ///
    /// `hint_rva`, when provided, is an optional caller-supplied candidate RVA
    /// (e.g. recovered from prior analysis of a specific sample). The hint is
    /// never trusted blindly: it is validated with [`Self::looks_like_dispatch_table`]
    /// using the same threshold the pattern-scan fallback and [`Self::validate`] use.
    /// If the hint is absent or fails validation, this falls back to scanning
    /// `.text`, `.rdata`, and any `.vmp*` / `.kbB*` sections for a candidate.
    ///
    /// Returns the virtual address of the dispatch table.
    pub fn locate(binary: &PEBinary, hint_rva: Option<u64>) -> Result<u64> {
        let image_base = binary.image_base()?;

        if let Some(rva) = hint_rva {
            let candidate_va = image_base + rva;
            if Self::looks_like_dispatch_table(binary, candidate_va, 8)
                || Self::looks_like_dispatch_table(binary, candidate_va, 4)
            {
                log::info!(
                    "Found dispatch table at VA: 0x{:x} (RVA hint: 0x{:x})",
                    candidate_va,
                    rva
                );
                return Ok(candidate_va);
            }
            log::warn!(
                "Dispatch table RVA hint 0x{:x} did not validate; falling back to pattern scan",
                rva
            );
        }

        // Fallback: try to find dispatch table signature patterns
        // Strategy 1: Look for dispatch table pattern in .text section
        if let Ok(text_data) = binary.get_section(".text") {
            if let Ok(va) = Self::find_dispatch_pattern(&text_data, binary, ".text") {
                return Ok(va);
            }
        }

        // Strategy 2: Look in .rdata section
        if let Ok(rdata_data) = binary.get_section(".rdata") {
            if let Ok(va) = Self::find_dispatch_pattern(&rdata_data, binary, ".rdata") {
                return Ok(va);
            }
        }

        // Strategy 3: Look in virtualized code sections (VMP 3.x)
        let sections = binary.get_all_sections().unwrap_or_default();
        for section_name in sections {
            if section_name.starts_with(".vmp") || section_name.starts_with(".kbB") {
                if let Ok(section_data) = binary.get_section(&section_name) {
                    if let Ok(va) = Self::find_dispatch_pattern(&section_data, binary, &section_name) {
                        return Ok(va);
                    }
                }
            }
        }

        // Fallback: return error - dispatch table not found
        anyhow::bail!("Could not locate dispatch table in any section")
    }

    /// Find dispatch table pattern in section data
    fn find_dispatch_pattern(section_data: &[u8], binary: &PEBinary, section_name: &str) -> Result<u64> {
        // Look for patterns that indicate a dispatch table
        // Dispatch tables typically have:
        // - Multiple consecutive pointers/addresses
        // - Regular spacing (4 or 8 bytes)
        // - Addresses pointing to code sections

        let image_base = binary.image_base()?;
        let mut potential_tables = Vec::new();

        // Scan for sequences of valid code pointers
        // Try both 4-byte and 8-byte entries
        for entry_size in &[4, 8] {
            for i in 0..section_data.len().saturating_sub(256 * entry_size) {
                let mut valid_count = 0;

                // Check if next 256 entries look like valid addresses
                for j in 0..256 {
                    let offset = i + j * entry_size;
                    if offset + entry_size > section_data.len() {
                        break;
                    }

                    let addr = if *entry_size == 4 {
                        let bytes = &section_data[offset..offset + 4];
                        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
                    } else {
                        let bytes = &section_data[offset..offset + 8];
                        u64::from_le_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                        ])
                    };

                    // Check if address is in reasonable range (image base ± 2GB)
                    if addr >= image_base && addr < image_base + 0x80000000 {
                        valid_count += 1;
                    }
                }

                if valid_count >= 200 {
                    potential_tables.push((i, valid_count, *entry_size));
                }
            }
        }

        if let Some((offset, _, _)) = potential_tables.first() {
            // Get section VA from binary
            let pe = binary.parse_pe()?;
            for section in &pe.sections {
                let sec_name = std::str::from_utf8(&section.name[..])
                    .unwrap_or("")
                    .trim_end_matches('\0');

                if sec_name == section_name {
                    let section_va = image_base + section.virtual_address as u64;
                    return Ok(section_va + *offset as u64);
                }
            }
        }

        anyhow::bail!("No dispatch table pattern found in {}", section_name)
    }

    /// Extract all 256 handler addresses from dispatch table
    ///
    /// Primary method: Unicorn CPU emulation
    /// Fallback: Static analysis with XOR key extraction
    pub fn extract_handlers(binary: &PEBinary, dispatch_table_va: u64) -> Result<Vec<u64>> {
        let image_base = binary.image_base()?;

        // Try primary method: Unicorn emulation
        log::info!("Attempting dispatch table extraction via Unicorn emulation...");

        // Get entry point from binary
        let entry_point_va = Self::get_entry_point(binary)?;

        match DispatchExtractorPy::extract(binary, dispatch_table_va, entry_point_va) {
            Ok(entries) => {
                log::info!("Successfully extracted {} entries via Unicorn", entries.len());

                // Validate against known data if available
                if let Ok(known_handlers) = Self::load_known_handlers() {
                    match DispatchExtractorPy::validate_entries(&entries, &known_handlers) {
                        Ok(true) => {
                            log::info!("Unicorn extraction validated successfully");
                            return Ok(DispatchExtractorPy::get_handler_addresses(&entries));
                        }
                        Ok(false) => {
                            log::warn!("Unicorn extraction validation failed, trying fallback");
                        }
                        Err(e) => {
                            log::warn!("Validation error: {}", e);
                        }
                    }
                } else {
                    // No known data, trust Unicorn extraction
                    return Ok(DispatchExtractorPy::get_handler_addresses(&entries));
                }
            }
            Err(e) => {
                log::warn!("Unicorn extraction failed: {}", e);
                log::info!("Falling back to static analysis...");
            }
        }

        // Fallback: Static analysis with XOR key extraction
        log::info!("Capturing XOR keys using static analysis...");
        let keys = XorKeyAnalyzer::capture_keys(binary, dispatch_table_va)?;

        // Validate keys
        match XorKeyAnalyzer::validate_keys(&keys, image_base) {
            Ok(true) => {
                log::info!("XOR key validation passed");
            }
            Ok(false) => {
                log::warn!("XOR key validation failed - some keys may be incorrect");
            }
            Err(e) => {
                log::warn!("Error validating keys: {}", e);
            }
        }

        // Get statistics
        let stats = XorKeyAnalyzer::get_key_statistics(&keys);
        log::info!(
            "Key statistics: {} total, {} valid, {} unique keys",
            stats.total_entries,
            stats.valid_entries,
            stats.unique_keys
        );

        // Return decrypted handler addresses
        Ok(XorKeyAnalyzer::get_handler_addresses(&keys))
    }

    /// Get entry point from PE header
    fn get_entry_point(binary: &PEBinary) -> Result<u64> {
        let pe = binary.parse_pe()?;
        let image_base = binary.image_base()?;

        let entry_point_rva = pe
            .header
            .optional_header
            .map(|oh| oh.standard_fields.address_of_entry_point as u64)
            .unwrap_or(0x1000);

        Ok(image_base + entry_point_rva)
    }

    /// Load known handlers from dispatch_table_info.json if available
    fn load_known_handlers() -> Result<Vec<u64>> {
        let path = "dispatch_table_info.json";
        if !std::path::Path::new(path).exists() {
            anyhow::bail!("Known handlers file not found");
        }

        let data = std::fs::read_to_string(path)?;
        let json: serde_json::Value = serde_json::from_str(&data)?;

        let handlers = json["handlers"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("No handlers array in JSON"))?
            .iter()
            .filter_map(|v| v.as_u64())
            .collect();

        Ok(handlers)
    }

    /// Check whether `table_va` looks like the start of a VMP dispatch table.
    ///
    /// Reads the first 256 entries of `entry_size` bytes (4 or 8) starting at
    /// `table_va` directly from the binary and counts how many decode to an
    /// address within `[image_base, image_base + 0x8000_0000)`. Returns `true`
    /// once at least 200 of the 256 entries fall in that range — the same
    /// threshold [`Self::validate`] applies to already-extracted handlers.
    ///
    /// A read failure (e.g. `table_va` lands outside every section) simply
    /// stops the scan early with whatever count was accumulated, so an
    /// out-of-bounds candidate naturally yields `false`.
    fn looks_like_dispatch_table(binary: &PEBinary, table_va: u64, entry_size: usize) -> bool {
        let image_base = match binary.image_base() {
            Ok(base) => base,
            Err(_) => return false,
        };

        let mut valid_count = 0;
        for i in 0..256u64 {
            let entry_va = match table_va.checked_add(i * entry_size as u64) {
                Some(va) => va,
                None => break,
            };

            let addr = match entry_size {
                8 => binary.read_u64(entry_va),
                4 => binary.read_u32(entry_va).map(u64::from),
                _ => return false,
            };

            let addr = match addr {
                Ok(addr) => addr,
                Err(_) => break,
            };

            if addr >= image_base && addr < image_base + 0x8000_0000 {
                valid_count += 1;
            }
        }

        valid_count >= 200
    }

    /// Validate dispatch table (check if addresses are reasonable)
    pub fn validate(binary: &PEBinary, handlers: &[u64]) -> Result<bool> {
        let image_base = binary.image_base()?;
        let mut valid_count = 0;

        for &handler_va in handlers {
            if handler_va == 0 {
                continue;
            }

            // Check if address is in reasonable range
            if handler_va >= image_base && handler_va < image_base + 0x80000000 {
                valid_count += 1;
            }
        }

        // At least 200 out of 256 should be valid
        Ok(valid_count >= 200)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal, valid PE32+ image in memory with a single section
    /// so `looks_like_dispatch_table` / `locate` can be exercised without a
    /// real VMP sample. `section_rva` is where the section is mapped and
    /// `section_data` becomes its raw (and virtual) content.
    fn build_minimal_pe(image_base: u64, section_rva: u32, section_data: &[u8]) -> PEBinary {
        const FILE_ALIGN: u32 = 0x200;
        const HEADERS_SIZE: u32 = 0x200;

        let mut raw = section_data.to_vec();
        while !raw.len().is_multiple_of(FILE_ALIGN as usize) {
            raw.push(0);
        }

        let mut buf = vec![0u8; HEADERS_SIZE as usize];

        // DOS header
        buf[0] = b'M';
        buf[1] = b'Z';
        let e_lfanew: u32 = 0x40;
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

        let mut off = e_lfanew as usize;
        buf[off..off + 4].copy_from_slice(b"PE\0\0");
        off += 4;

        // COFF header
        buf[off..off + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
        off += 2;
        buf[off..off + 2].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        off += 2;
        off += 4; // TimeDateStamp
        off += 4; // PointerToSymbolTable
        off += 4; // NumberOfSymbols
        buf[off..off + 2].copy_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader
        off += 2;
        buf[off..off + 2].copy_from_slice(&0x0022u16.to_le_bytes()); // Characteristics
        off += 2;

        // Optional header (PE32+), standard fields
        buf[off..off + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // Magic
        off += 2;
        off += 1 + 1; // Major/MinorLinkerVersion
        off += 4; // SizeOfCode
        off += 4; // SizeOfInitializedData
        off += 4; // SizeOfUninitializedData
        buf[off..off + 4].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
        off += 4;
        off += 4; // BaseOfCode

        // Optional header, windows-specific fields
        buf[off..off + 8].copy_from_slice(&image_base.to_le_bytes()); // ImageBase
        off += 8;
        buf[off..off + 4].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        off += 4;
        buf[off..off + 4].copy_from_slice(&FILE_ALIGN.to_le_bytes()); // FileAlignment
        off += 4;
        off += 2 + 2 + 2 + 2 + 2 + 2; // OS/Image/Subsystem versions
        off += 4; // Win32VersionValue
        let size_of_image = section_rva + raw.len() as u32 + 0x1000;
        buf[off..off + 4].copy_from_slice(&size_of_image.to_le_bytes()); // SizeOfImage
        off += 4;
        buf[off..off + 4].copy_from_slice(&HEADERS_SIZE.to_le_bytes()); // SizeOfHeaders
        off += 4;
        off += 4; // CheckSum
        buf[off..off + 2].copy_from_slice(&2u16.to_le_bytes()); // Subsystem
        off += 2;
        off += 2; // DllCharacteristics
        off += 8 + 8 + 8 + 8; // Stack/Heap reserve+commit
        off += 4; // LoaderFlags
        buf[off..off + 4].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        off += 4;
        off += 16 * 8; // Data directories (all zero)

        // Section header
        let name = b".test\0\0\0";
        buf[off..off + 8].copy_from_slice(name);
        off += 8;
        buf[off..off + 4].copy_from_slice(&(raw.len() as u32).to_le_bytes()); // VirtualSize
        off += 4;
        buf[off..off + 4].copy_from_slice(&section_rva.to_le_bytes()); // VirtualAddress
        off += 4;
        buf[off..off + 4].copy_from_slice(&(raw.len() as u32).to_le_bytes()); // SizeOfRawData
        off += 4;
        buf[off..off + 4].copy_from_slice(&HEADERS_SIZE.to_le_bytes()); // PointerToRawData
        off += 4;
        off += 4 + 4 + 2 + 2; // Relocations/Linenumbers pointers+counts
        buf[off..off + 4].copy_from_slice(&0xC0000040u32.to_le_bytes()); // Characteristics
        off += 4;
        let _ = off;

        buf.extend_from_slice(&raw);

        PEBinary {
            path: "<test-fixture>".to_string(),
            data: buf,
        }
    }

    /// Build 256 pointer-sized entries; the first `valid_count` decode into
    /// `[image_base, image_base + 0x8000_0000)`, the rest are clearly invalid.
    fn make_entries(image_base: u64, valid_count: usize, entry_size: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(256 * entry_size);
        for i in 0..256u64 {
            let value: u64 = if (i as usize) < valid_count {
                image_base + 0x1000 + i * 0x10
            } else {
                0x1000
            };
            if entry_size == 8 {
                data.extend_from_slice(&value.to_le_bytes());
            } else {
                data.extend_from_slice(&(value as u32).to_le_bytes());
            }
        }
        data
    }

    #[test]
    fn looks_like_dispatch_table_true_for_valid_pointer_run() {
        let image_base = 0x1_4000_0000u64;
        let section_rva = 0x1000u32;
        let entries = make_entries(image_base, 256, 8);
        let binary = build_minimal_pe(image_base, section_rva, &entries);

        let table_va = image_base + section_rva as u64;
        assert!(DispatchTableLocator::looks_like_dispatch_table(&binary, table_va, 8));
    }

    #[test]
    fn looks_like_dispatch_table_false_outside_all_sections() {
        let image_base = 0x1_4000_0000u64;
        let section_rva = 0x1000u32;
        let entries = make_entries(image_base, 256, 8);
        let binary = build_minimal_pe(image_base, section_rva, &entries);

        // Far outside the mapped section / SizeOfImage.
        let table_va = image_base + 0x00F0_0000;
        assert!(!DispatchTableLocator::looks_like_dispatch_table(&binary, table_va, 8));
    }

    #[test]
    fn looks_like_dispatch_table_false_below_threshold() {
        let image_base = 0x1_4000_0000u64;
        let section_rva = 0x1000u32;
        // Only 100 of 256 entries are valid pointers; threshold is 200.
        let entries = make_entries(image_base, 100, 8);
        let binary = build_minimal_pe(image_base, section_rva, &entries);

        let table_va = image_base + section_rva as u64;
        assert!(!DispatchTableLocator::looks_like_dispatch_table(&binary, table_va, 8));
    }

    #[test]
    fn locate_returns_hint_when_it_validates() {
        let image_base = 0x1_4000_0000u64;
        let section_rva = 0x1000u32;
        let entries = make_entries(image_base, 256, 8);
        let binary = build_minimal_pe(image_base, section_rva, &entries);

        let va = DispatchTableLocator::locate(&binary, Some(section_rva as u64)).expect("hint should validate");
        assert_eq!(va, image_base + section_rva as u64);
    }

    #[test]
    fn locate_errors_when_hint_invalid_and_no_pattern_found() {
        let image_base = 0x1_4000_0000u64;
        let section_rva = 0x1000u32;
        // No valid pointer run anywhere in the (single, non-.text/.rdata/.vmp*) section.
        let entries = make_entries(image_base, 0, 8);
        let binary = build_minimal_pe(image_base, section_rva, &entries);

        let bad_hint = 0x0090_0000u64; // does not validate, and outside the image
        let result = DispatchTableLocator::locate(&binary, Some(bad_hint));
        assert!(result.is_err());
    }
}
