//! Shared helpers for integration tests.

use std::io::Write;
use tempfile::NamedTempFile;

/// Build a minimal, valid PE32+ image in memory with a single `.test`
/// section, then write it to a temporary file on disk so `assert_cmd`
/// can hand its path to the `vmp_devirt` binary.
///
/// Mirrors `src/pe_loader.rs::tests::build_minimal_pe` — kept in sync
/// but duplicated because integration tests cannot reach `#[cfg(test)]`
/// helpers in the library crate.
///
/// The generated image:
///   - is 64-bit (Machine = 0x8664, magic = 0x20B),
///   - places `section_data` at `image_base + section_rva`,
///   - sets `AddressOfEntryPoint = 0x1000` (matches `section_rva`),
///   - has no `.vmp0`/`.vmp1` and no VMP entry-stub bytes, so the
///     detector will confidently return `Unknown` with confidence 0.
pub fn write_minimal_pe(image_base: u64, section_rva: u32, section_data: &[u8]) -> NamedTempFile {
    let bytes = build_minimal_pe_bytes(true, image_base, section_rva, section_data);
    let mut file = tempfile::Builder::new()
        .prefix("vmp_devirt_fixture_")
        .suffix(".exe")
        .tempfile()
        .expect("create tempfile");
    file.write_all(&bytes).expect("write PE bytes");
    file.flush().expect("flush tempfile");
    file
}

fn build_minimal_pe_bytes(is_64: bool, image_base: u64, section_rva: u32, section_data: &[u8]) -> Vec<u8> {
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
    buf[off..off + 2].copy_from_slice(&1u16.to_le_bytes());
    off += 2;
    off += 4 + 4 + 4;
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
    off += 2;
    off += 4 + 4 + 4;
    buf[off..off + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    off += 4;
    off += 4;
    if !is_64 {
        off += 4;
    }

    // Optional header, windows-specific fields
    if is_64 {
        buf[off..off + 8].copy_from_slice(&image_base.to_le_bytes());
        off += 8;
    } else {
        buf[off..off + 4].copy_from_slice(&(image_base as u32).to_le_bytes());
        off += 4;
    }
    buf[off..off + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    off += 4;
    buf[off..off + 4].copy_from_slice(&FILE_ALIGN.to_le_bytes());
    off += 4;
    off += 12;
    off += 4;
    let size_of_image = section_rva + raw.len() as u32 + 0x1000;
    buf[off..off + 4].copy_from_slice(&size_of_image.to_le_bytes());
    off += 4;
    buf[off..off + 4].copy_from_slice(&HEADERS_SIZE.to_le_bytes());
    off += 4;
    off += 4;
    buf[off..off + 2].copy_from_slice(&2u16.to_le_bytes());
    off += 2;
    off += 2;
    if is_64 {
        off += 8 + 8 + 8 + 8;
    } else {
        off += 4 + 4 + 4 + 4;
    }
    off += 4;
    buf[off..off + 4].copy_from_slice(&16u32.to_le_bytes());
    off += 4;
    off += 16 * 8;

    debug_assert_eq!(off - opt_header_start, size_of_optional_header as usize);

    // Section header
    let name = b".test\0\0\0";
    buf[off..off + 8].copy_from_slice(name);
    off += 8;
    buf[off..off + 4].copy_from_slice(&(raw.len() as u32).to_le_bytes());
    off += 4;
    buf[off..off + 4].copy_from_slice(&section_rva.to_le_bytes());
    off += 4;
    buf[off..off + 4].copy_from_slice(&(raw.len() as u32).to_le_bytes());
    off += 4;
    buf[off..off + 4].copy_from_slice(&HEADERS_SIZE.to_le_bytes());
    off += 4;
    off += 4 + 4 + 2 + 2;
    buf[off..off + 4].copy_from_slice(&0xC0000040u32.to_le_bytes());
    off += 4;
    let _ = off;

    buf.extend_from_slice(&raw);
    buf
}
