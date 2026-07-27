//! PE Binary Loader
//!
//! Handles PE binary parsing and VA mapping.

use anyhow::{Context, Result};
use goblin::pe::PE;
use std::fs;
use std::path::Path;

/// Target architecture bitness of a loaded PE image.
///
/// Determined from the optional header's `Magic` field (0x10B for PE32/x86,
/// 0x20B for PE32+/x64), surfaced by goblin as `PE::is_64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bitness {
    /// 32-bit PE32 image (x86).
    X86,
    /// 64-bit PE32+ image (x86-64).
    X64,
}

/// Loaded PE binary
pub struct PEBinary {
    /// File path
    pub path: String,
    /// Binary data
    pub data: Vec<u8>,
}

impl PEBinary {
    /// Load PE binary from file
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let data = fs::read(&path).context(format!("Failed to read file: {}", path_str))?;

        // Verify PE header
        let _ = PE::parse(&data).context("Failed to parse PE binary")?;

        Ok(PEBinary { path: path_str, data })
    }

    /// Parse PE header (on demand)
    pub fn parse_pe(&self) -> Result<PE<'_>> {
        PE::parse(&self.data).context("Failed to parse PE binary")
    }

    /// Get section data by name
    pub fn get_section(&self, name: &str) -> Result<Vec<u8>> {
        let pe = self.parse_pe()?;

        for section in &pe.sections {
            let section_name = std::str::from_utf8(&section.name[..])
                .unwrap_or("")
                .trim_end_matches('\0');

            if section_name == name {
                let start = section.pointer_to_raw_data as usize;
                let end = start
                    .checked_add(section.size_of_raw_data as usize)
                    .with_context(|| format!("Section {}: raw-size overflow", name))?;
                return self
                    .data
                    .get(start..end)
                    .map(|s| s.to_vec())
                    .with_context(|| format!("Section {}: bounds out of file", name));
            }
        }

        anyhow::bail!("Section not found: {}", name)
    }

    /// Get all section names
    pub fn get_all_sections(&self) -> Result<Vec<String>> {
        let pe = self.parse_pe()?;
        let mut sections = Vec::new();

        for section in &pe.sections {
            let name = std::str::from_utf8(&section.name[..])
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string();

            if !name.is_empty() {
                sections.push(name);
            }
        }

        Ok(sections)
    }

    /// Get the target bitness (x86 PE32 vs x86-64 PE32+) from the optional
    /// header's magic, via goblin's `PE::is_64`.
    pub fn bitness(&self) -> Result<Bitness> {
        let pe = self.parse_pe()?;
        Ok(if pe.is_64 { Bitness::X64 } else { Bitness::X86 })
    }

    /// Get image base
    pub fn image_base(&self) -> Result<u64> {
        let pe = self.parse_pe()?;
        match pe.header.optional_header {
            Some(oh) => Ok(oh.windows_fields.image_base),
            None => {
                let default_base = if pe.is_64 { 0x140000000 } else { 0x00400000 };
                Ok(default_base)
            }
        }
    }

    /// Locate the section containing `va`, returning its file offset and the
    /// VA immediately past the end of its effective (virtual-vs-raw clamped)
    /// span.
    fn locate_section(&self, va: u64) -> Result<(usize, u64)> {
        let pe = self.parse_pe()?;
        let image_base = self.image_base()?;

        for section in &pe.sections {
            let section_start = image_base
                .checked_add(section.virtual_address as u64)
                .context("Section VA overflow")?;
            // Guard the virtual-vs-raw mismatch (malicious PE may inflate virtual_size)
            let raw_span = section.size_of_raw_data as u64;
            let virt_span = section.virtual_size as u64;
            let effective_span = virt_span.min(raw_span);
            let section_end = section_start
                .checked_add(effective_span)
                .context("Section end overflow")?;

            if va >= section_start && va < section_end {
                let offset = va - section_start;
                let file_offset = (section.pointer_to_raw_data as usize)
                    .checked_add(offset as usize)
                    .context("File-offset overflow")?;
                return Ok((file_offset, section_end));
            }
        }

        anyhow::bail!("Invalid VA: 0x{:x}", va)
    }

    /// Convert VA to file offset
    pub fn va_to_offset(&self, va: u64) -> Result<usize> {
        self.locate_section(va).map(|(file_offset, _)| file_offset)
    }

    /// Read bytes from VA
    pub fn read_bytes(&self, va: u64, size: usize) -> Result<Vec<u8>> {
        let offset = self.va_to_offset(va)?;
        let end = offset.checked_add(size).context("Read size overflow")?;
        self.data
            .get(offset..end)
            .map(|s| s.to_vec())
            .with_context(|| format!("Out-of-bounds read: {} bytes @ 0x{:x}", size, va))
    }

    /// Read up to `max` bytes from VA, returning as many bytes as are
    /// available in the containing section (never more than `max`).
    ///
    /// Unlike [`Self::read_bytes`], this never errors just because fewer
    /// than `max` bytes remain — it only errors if `va` is not located in
    /// any section. Used by handler classification, where a short handler
    /// near a section boundary should still be readable rather than
    /// wrongly reported as unreadable.
    pub fn read_bytes_up_to(&self, va: u64, max: usize) -> Result<Vec<u8>> {
        let (file_offset, section_end_va) = self.locate_section(va)?;
        let remaining_in_section = (section_end_va - va) as usize;
        let take = max.min(remaining_in_section);
        let end = file_offset.saturating_add(take).min(self.data.len());
        let start = file_offset.min(end);
        Ok(self.data.get(start..end).map(|s| s.to_vec()).unwrap_or_default())
    }

    /// Read u8 from VA
    pub fn read_u8(&self, va: u64) -> Result<u8> {
        let bytes = self.read_bytes(va, 1)?;
        bytes
            .first()
            .copied()
            .with_context(|| format!("Empty read @ 0x{:x}", va))
    }

    /// Read u32 from VA (little-endian)
    pub fn read_u32(&self, va: u64) -> Result<u32> {
        let bytes = self.read_bytes(va, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read u64 from VA (little-endian)
    pub fn read_u64(&self, va: u64) -> Result<u64> {
        let bytes = self.read_bytes(va, 8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Resolve the PE entry point virtual address (`image_base + AddressOfEntryPoint`).
    pub fn entry_point_va(&self) -> Result<u64> {
        let pe = self.parse_pe()?;
        let optional_header = pe
            .header
            .optional_header
            .context("PE has no optional header; cannot resolve entry point")?;
        let entry_rva = optional_header.standard_fields.address_of_entry_point;
        let image_base = optional_header.windows_fields.image_base;
        image_base
            .checked_add(entry_rva as u64)
            .context("Entry point VA overflow")
    }

    /// Read up to `count` bytes starting at the PE entry point
    /// (`AddressOfEntryPoint`), returning as many bytes as remain in the
    /// containing section (never more than `count`).
    ///
    /// Uses [`Self::read_bytes_up_to`] rather than the strict
    /// [`Self::read_bytes`] so an entry-code section shorter than `count`
    /// (e.g. a small thunk near the end of `.text`) still yields the
    /// available prefix. The strict variant would return `Err` and cause
    /// every entry-stub heuristic in the version detector to be silently
    /// skipped for otherwise-legitimate samples.
    pub fn entry_point_bytes(&self, count: usize) -> Result<Vec<u8>> {
        let entry_va = self.entry_point_va()?;
        self.read_bytes_up_to(entry_va, count)
    }

    /// Get the raw `Characteristics` flags (IMAGE_SCN_*) for a named section.
    pub fn section_characteristics(&self, name: &str) -> Result<u32> {
        let pe = self.parse_pe()?;

        for section in &pe.sections {
            let section_name = std::str::from_utf8(&section.name[..])
                .unwrap_or("")
                .trim_end_matches('\0');

            if section_name == name {
                return Ok(section.characteristics);
            }
        }

        anyhow::bail!("Section not found: {}", name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal, valid PE image (PE32 when `is_64` is false, PE32+
    /// otherwise) in memory with a single section, so `bitness`/`image_base`/
    /// `read_bytes_up_to` can be exercised without a real sample on disk.
    fn build_minimal_pe(is_64: bool, image_base: u64, section_rva: u32, section_data: &[u8]) -> PEBinary {
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
        let machine: u16 = if is_64 { 0x8664 } else { 0x014c };
        buf[off..off + 2].copy_from_slice(&machine.to_le_bytes());
        off += 2;
        buf[off..off + 2].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        off += 2;
        off += 4; // TimeDateStamp
        off += 4; // PointerToSymbolTable
        off += 4; // NumberOfSymbols
        let size_of_optional_header: u16 = if is_64 { 0xF0 } else { 0xE0 };
        buf[off..off + 2].copy_from_slice(&size_of_optional_header.to_le_bytes());
        off += 2;
        let characteristics: u16 = if is_64 { 0x0022 } else { 0x0102 };
        buf[off..off + 2].copy_from_slice(&characteristics.to_le_bytes());
        off += 2;

        let opt_header_start = off;

        // Optional header, standard fields
        let magic: u16 = if is_64 { 0x020B } else { 0x010B };
        buf[off..off + 2].copy_from_slice(&magic.to_le_bytes());
        off += 2;
        off += 1 + 1; // Major/MinorLinkerVersion
        off += 4; // SizeOfCode
        off += 4; // SizeOfInitializedData
        off += 4; // SizeOfUninitializedData
        buf[off..off + 4].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
        off += 4;
        off += 4; // BaseOfCode
        if !is_64 {
            off += 4; // BaseOfData (PE32 only)
        }

        // Optional header, windows-specific fields
        if is_64 {
            buf[off..off + 8].copy_from_slice(&image_base.to_le_bytes());
            off += 8;
        } else {
            buf[off..off + 4].copy_from_slice(&(image_base as u32).to_le_bytes());
            off += 4;
        }
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
        if is_64 {
            off += 8 + 8 + 8 + 8; // Stack/Heap reserve+commit
        } else {
            off += 4 + 4 + 4 + 4;
        }
        off += 4; // LoaderFlags
        buf[off..off + 4].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        off += 4;
        off += 16 * 8; // Data directories (all zero)

        debug_assert_eq!(off - opt_header_start, size_of_optional_header as usize);

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

    #[test]
    fn test_pe_load() {
        // Stub: requires a real PE fixture. See AUDIT_REPORT.md Q13.
    }

    #[test]
    fn bitness_detects_x64_for_pe32plus() {
        let binary = build_minimal_pe(true, 0x1_4000_0000, 0x1000, &[0xAAu8; 16]);
        assert_eq!(binary.bitness().unwrap(), Bitness::X64);
        assert_eq!(binary.image_base().unwrap(), 0x1_4000_0000);
    }

    #[test]
    fn bitness_detects_x86_for_pe32() {
        let binary = build_minimal_pe(false, 0x0040_0000, 0x1000, &[0xAAu8; 16]);
        assert_eq!(binary.bitness().unwrap(), Bitness::X86);
        assert_eq!(binary.image_base().unwrap(), 0x0040_0000);
    }

    #[test]
    fn read_bytes_up_to_truncates_at_section_boundary() {
        let image_base = 0x1_4000_0000u64;
        let section_rva = 0x1000u32;
        let binary = build_minimal_pe(true, image_base, section_rva, &[0xAAu8; 10]);
        let section_va = image_base + section_rva as u64;

        // Discover the (file-alignment padded) section length.
        let full = binary.read_bytes_up_to(section_va, 1 << 20).unwrap();
        let section_len = full.len();
        assert!(section_len >= 10);

        // Five bytes before the end: requesting more than that must be clamped.
        let near_end_va = section_va + (section_len as u64 - 5);
        let truncated = binary.read_bytes_up_to(near_end_va, 100).unwrap();
        assert_eq!(truncated.len(), 5);
    }

    #[test]
    fn read_bytes_up_to_returns_exactly_max_when_available() {
        let image_base = 0x1_4000_0000u64;
        let section_rva = 0x1000u32;
        let binary = build_minimal_pe(true, image_base, section_rva, &[0xAAu8; 10]);
        let section_va = image_base + section_rva as u64;

        let partial = binary.read_bytes_up_to(section_va, 3).unwrap();
        assert_eq!(partial, vec![0xAA, 0xAA, 0xAA]);
    }

    #[test]
    fn read_bytes_up_to_errors_outside_any_section() {
        let image_base = 0x1_4000_0000u64;
        let binary = build_minimal_pe(true, image_base, 0x1000, &[0xAAu8; 10]);
        assert!(binary.read_bytes_up_to(image_base + 0x00F0_0000, 10).is_err());
    }
}
