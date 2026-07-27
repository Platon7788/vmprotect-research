//! Shared minimal-PE fixture builder for lib-side tests.
//!
//! Split from `pe_loader.rs` via `#[cfg(test)] #[path]` so the impl file
//! stays under the crate's 500-line ceiling. Single authoritative source
//! for the PE32/PE32+ generator previously duplicated in
//! `dispatch_table.rs::tests` and, in a slightly different form, in
//! `tests/common/mod.rs`. The integration-test copy in
//! `tests/common/mod.rs` cannot import from here (it links the crate
//! without `#[cfg(test)]`), so it stays as a documented twin — see the
//! comment at the top of that file.

use super::PEBinary;

/// Build a minimal, valid PE image (PE32 when `is_64` is false, PE32+
/// otherwise) in memory with a single `.test` section, so
/// `bitness`/`image_base`/`read_bytes_up_to` can be exercised without
/// a real sample on disk.
pub fn build_minimal_pe(is_64: bool, image_base: u64, section_rva: u32, section_data: &[u8]) -> PEBinary {
    const FILE_ALIGN: u32 = 0x200;
    const HEADERS_SIZE: u32 = 0x200;

    let mut raw = section_data.to_vec();
    while raw.len() % FILE_ALIGN as usize != 0 {
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

/// Build a minimal PE with N named sections, each given a caller-chosen
/// `Characteristics` value instead of the fixed 0xC0000040 (R+W+CNT_INIT_DATA)
/// every other builder in this file uses. Needed for tests that gate on
/// `IMAGE_SCN_MEM_EXECUTE` (e.g. the structural VMP dispatcher scan, which
/// only looks at RX sections) -- none of the other fixtures ever set that
/// bit, so a rule scoped to "executable sections only" can't be exercised
/// through them. Otherwise identical layout to
/// [`build_minimal_pe_with_named_sections`].
pub fn build_minimal_pe_with_section_characteristics(
    is_64: bool,
    image_base: u64,
    sections: &[(&str, &[u8], u32)],
) -> PEBinary {
    assert!(!sections.is_empty(), "at least one section required");
    for (name, _, _) in sections {
        assert!(
            name.len() <= 8,
            "section name '{name}' exceeds the 8-byte PE section-name field"
        );
    }

    const FILE_ALIGN: u32 = 0x200;
    const SECTION_ALIGN: u32 = 0x1000;

    let size_of_optional_header: u32 = if is_64 { 0xF0 } else { 0xE0 };
    let coff_and_opt = 4 + 20 + size_of_optional_header;
    let section_headers_size = (sections.len() as u32) * 40;
    let raw_headers_size = 0x40 + coff_and_opt + section_headers_size;
    // Round UP to file alignment: `div_ceil * FILE_ALIGN` handles the
    // already-aligned case correctly (unlike `next_multiple_of`).
    let headers_size = raw_headers_size.div_ceil(FILE_ALIGN) * FILE_ALIGN;

    // Layout every section's RVA and file offset before writing the
    // header table -- SizeOfImage depends on the last section's tail.
    let mut section_rvas = Vec::with_capacity(sections.len());
    let mut section_file_offsets = Vec::with_capacity(sections.len());
    let mut section_raw_sizes = Vec::with_capacity(sections.len());
    let mut cur_rva: u32 = SECTION_ALIGN;
    let mut cur_file: u32 = headers_size;
    for (_, data, _) in sections {
        // At least one file-alignment block per section, even when the
        // body would fit in less -- goblin rejects zero-sized raw sections.
        let raw = (data.len() as u32).max(1).div_ceil(FILE_ALIGN) * FILE_ALIGN;
        section_rvas.push(cur_rva);
        section_file_offsets.push(cur_file);
        section_raw_sizes.push(raw);
        cur_rva = (cur_rva + raw).div_ceil(SECTION_ALIGN) * SECTION_ALIGN;
        cur_file += raw;
    }
    let size_of_image = cur_rva;

    let mut buf = vec![0u8; headers_size as usize];

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
    buf[off..off + 2].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    off += 2;
    off += 4 + 4 + 4; // TimeDateStamp + PointerToSymbolTable + NumberOfSymbols
    buf[off..off + 2].copy_from_slice(&(size_of_optional_header as u16).to_le_bytes());
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
    off += 4 + 4 + 4; // SizeOfCode + SizeOfInitializedData + SizeOfUninitializedData
    buf[off..off + 4].copy_from_slice(&section_rvas[0].to_le_bytes()); // AddressOfEntryPoint
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
    buf[off..off + 4].copy_from_slice(&SECTION_ALIGN.to_le_bytes()); // SectionAlignment
    off += 4;
    buf[off..off + 4].copy_from_slice(&FILE_ALIGN.to_le_bytes()); // FileAlignment
    off += 4;
    off += 2 + 2 + 2 + 2 + 2 + 2; // OS/Image/Subsystem versions
    off += 4; // Win32VersionValue
    buf[off..off + 4].copy_from_slice(&size_of_image.to_le_bytes()); // SizeOfImage
    off += 4;
    buf[off..off + 4].copy_from_slice(&headers_size.to_le_bytes()); // SizeOfHeaders
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

    // Section headers
    for (i, (name, _, characteristics)) in sections.iter().enumerate() {
        let mut name_field = [0u8; 8];
        name_field[..name.len()].copy_from_slice(name.as_bytes());
        buf[off..off + 8].copy_from_slice(&name_field);
        off += 8;
        buf[off..off + 4].copy_from_slice(&section_raw_sizes[i].to_le_bytes()); // VirtualSize
        off += 4;
        buf[off..off + 4].copy_from_slice(&section_rvas[i].to_le_bytes()); // VirtualAddress
        off += 4;
        buf[off..off + 4].copy_from_slice(&section_raw_sizes[i].to_le_bytes()); // SizeOfRawData
        off += 4;
        buf[off..off + 4].copy_from_slice(&section_file_offsets[i].to_le_bytes()); // PointerToRawData
        off += 4;
        off += 4 + 4 + 2 + 2; // Relocations/Linenumbers pointers+counts
        buf[off..off + 4].copy_from_slice(&characteristics.to_le_bytes());
        off += 4;
    }
    let _ = off;

    // Section bodies (each padded to its raw size)
    for i in 0..sections.len() {
        let mut body = sections[i].1.to_vec();
        while (body.len() as u32) < section_raw_sizes[i] {
            body.push(0);
        }
        buf.extend_from_slice(&body);
    }

    PEBinary {
        path: "<test-fixture>".to_string(),
        data: buf,
    }
}

/// Build a minimal PE with a caller-chosen 8-byte section name (padded
/// with `\0` if shorter). Otherwise identical to [`build_minimal_pe`] —
/// single section, entry point at RVA 0x1000, `Characteristics`
/// 0xC0000040 (R+W+CNT_INIT_DATA).
///
/// Section names longer than 8 bytes panic — PE section names are a
/// fixed 8-byte field; the string-table escape is not supported by this
/// fixture. Reserved for tests where the section name itself is the
/// signal under test (Themida `.themida`, Denuvo `.vm`, BattlEye `.be0`,
/// ...) and the `.test` name in [`build_minimal_pe`] would defeat the
/// point of the rule.
pub fn build_minimal_pe_with_section_name(
    is_64: bool,
    image_base: u64,
    section_name: &str,
    section_data: &[u8],
) -> PEBinary {
    build_minimal_pe_with_named_sections(is_64, image_base, &[(section_name, section_data)])
}

/// Build a minimal PE with N named sections laid out contiguously from
/// RVA 0x1000, each aligned to `SectionAlignment` (0x1000). Section
/// characteristics are uniform (0xC0000040 = R+W+CNT_INIT_DATA) — same
/// as the single-section fixture. Entry point stays at the first
/// section's RVA (0x1000).
///
/// Used by tests that must exercise rules keyed on multiple sections
/// (e.g. Vanguard's "two `.stub` sections" fingerprint).
pub fn build_minimal_pe_with_named_sections(is_64: bool, image_base: u64, sections: &[(&str, &[u8])]) -> PEBinary {
    assert!(!sections.is_empty(), "at least one section required");
    for (name, _) in sections {
        assert!(
            name.len() <= 8,
            "section name '{name}' exceeds the 8-byte PE section-name field"
        );
    }

    const FILE_ALIGN: u32 = 0x200;
    const SECTION_ALIGN: u32 = 0x1000;

    let size_of_optional_header: u32 = if is_64 { 0xF0 } else { 0xE0 };
    let coff_and_opt = 4 + 20 + size_of_optional_header;
    let section_headers_size = (sections.len() as u32) * 40;
    let raw_headers_size = 0x40 + coff_and_opt + section_headers_size;
    // Round UP to file alignment: `div_ceil * FILE_ALIGN` handles the
    // already-aligned case correctly (unlike `next_multiple_of`).
    let headers_size = raw_headers_size.div_ceil(FILE_ALIGN) * FILE_ALIGN;

    // Layout every section's RVA and file offset before writing the
    // header table — SizeOfImage depends on the last section's tail.
    let mut section_rvas = Vec::with_capacity(sections.len());
    let mut section_file_offsets = Vec::with_capacity(sections.len());
    let mut section_raw_sizes = Vec::with_capacity(sections.len());
    let mut cur_rva: u32 = SECTION_ALIGN;
    let mut cur_file: u32 = headers_size;
    for (_, data) in sections {
        // At least one file-alignment block per section, even when the
        // body would fit in less — goblin rejects zero-sized raw sections.
        let raw = (data.len() as u32).max(1).div_ceil(FILE_ALIGN) * FILE_ALIGN;
        section_rvas.push(cur_rva);
        section_file_offsets.push(cur_file);
        section_raw_sizes.push(raw);
        cur_rva = (cur_rva + raw).div_ceil(SECTION_ALIGN) * SECTION_ALIGN;
        cur_file += raw;
    }
    let size_of_image = cur_rva;

    let mut buf = vec![0u8; headers_size as usize];

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
    buf[off..off + 2].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    off += 2;
    off += 4 + 4 + 4; // TimeDateStamp + PointerToSymbolTable + NumberOfSymbols
    buf[off..off + 2].copy_from_slice(&(size_of_optional_header as u16).to_le_bytes());
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
    off += 4 + 4 + 4; // SizeOfCode + SizeOfInitializedData + SizeOfUninitializedData
    buf[off..off + 4].copy_from_slice(&section_rvas[0].to_le_bytes()); // AddressOfEntryPoint
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
    buf[off..off + 4].copy_from_slice(&SECTION_ALIGN.to_le_bytes()); // SectionAlignment
    off += 4;
    buf[off..off + 4].copy_from_slice(&FILE_ALIGN.to_le_bytes()); // FileAlignment
    off += 4;
    off += 2 + 2 + 2 + 2 + 2 + 2; // OS/Image/Subsystem versions
    off += 4; // Win32VersionValue
    buf[off..off + 4].copy_from_slice(&size_of_image.to_le_bytes()); // SizeOfImage
    off += 4;
    buf[off..off + 4].copy_from_slice(&headers_size.to_le_bytes()); // SizeOfHeaders
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

    // Section headers
    for (i, (name, _)) in sections.iter().enumerate() {
        let mut name_field = [0u8; 8];
        name_field[..name.len()].copy_from_slice(name.as_bytes());
        buf[off..off + 8].copy_from_slice(&name_field);
        off += 8;
        buf[off..off + 4].copy_from_slice(&section_raw_sizes[i].to_le_bytes()); // VirtualSize
        off += 4;
        buf[off..off + 4].copy_from_slice(&section_rvas[i].to_le_bytes()); // VirtualAddress
        off += 4;
        buf[off..off + 4].copy_from_slice(&section_raw_sizes[i].to_le_bytes()); // SizeOfRawData
        off += 4;
        buf[off..off + 4].copy_from_slice(&section_file_offsets[i].to_le_bytes()); // PointerToRawData
        off += 4;
        off += 4 + 4 + 2 + 2; // Relocations/Linenumbers pointers+counts
        buf[off..off + 4].copy_from_slice(&0xC0000040u32.to_le_bytes()); // Characteristics
        off += 4;
    }
    let _ = off;

    // Section bodies (each padded to its raw size)
    for i in 0..sections.len() {
        let mut body = sections[i].1.to_vec();
        while (body.len() as u32) < section_raw_sizes[i] {
            body.push(0);
        }
        buf.extend_from_slice(&body);
    }

    PEBinary {
        path: "<test-fixture>".to_string(),
        data: buf,
    }
}
