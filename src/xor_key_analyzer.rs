//! Dispatch Table XOR Key Extraction
//!
//! Extracts all 256 XOR keys used to encrypt handler addresses
//! in the VMP dispatch table using static analysis and pattern matching.
//!
//! NOTE: despite the file name, this module does NOT use the Unicorn engine —
//! it performs static pattern matching on x86-64 XOR-imm32 encodings.
//! Rename to `xor_key_analyzer.rs` planned (see AUDIT_REPORT.md, Q7).

use crate::{Bitness, PEBinary};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Captured XOR key entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XorKeyEntry {
    /// Opcode index (0-255)
    pub opcode: u8,
    /// XOR key value
    pub key: u64,
    /// Encrypted handler address (before XOR)
    pub encrypted: u64,
    /// Decrypted handler address (after XOR)
    pub decrypted: u64,
}

/// A byte-prefix XOR-immediate pattern to scan for, plus whether the
/// matched 32-bit immediate should be sign-extended to 64 bits when forming
/// the key (x86-64 `REX.W`-prefixed forms sign-extend per the Intel SDM;
/// plain 32-bit x86 forms do not).
struct XorPattern {
    /// Fixed opcode-prefix bytes preceding the 4-byte little-endian immediate.
    prefix: &'static [u8],
    /// Whether to sign-extend the matched `imm32` into the upper 32 bits of the key.
    sign_extend: bool,
}

/// Unicorn-based key extractor (static analysis version).
///
/// Fields kept for API compatibility with the instance-based flow (see `new`);
/// current production path uses associated (static) functions.
#[allow(dead_code)]
pub struct XorKeyAnalyzer {
    /// Captured XOR keys
    keys: Vec<XorKeyEntry>,
    /// Dispatch table VA
    dispatch_table_va: u64,
    /// Image base
    image_base: u64,
}

impl XorKeyAnalyzer {
    /// Create new key extractor
    pub fn new(dispatch_table_va: u64, image_base: u64) -> Self {
        XorKeyAnalyzer {
            keys: Vec::new(),
            dispatch_table_va,
            image_base,
        }
    }

    /// Extract XOR keys from dispatch table using pattern analysis
    ///
    /// Strategy:
    /// 1. Read all 256 dispatch table entries
    /// 2. Analyze code patterns that populate the table
    /// 3. Extract XOR keys from immediate values in XOR instructions
    /// 4. Validate decrypted addresses are in code sections
    pub fn capture_keys(binary: &PEBinary, dispatch_table_va: u64) -> Result<Vec<XorKeyEntry>> {
        let image_base = binary.image_base()?;
        let bitness = binary.bitness()?;
        let entry_size: u64 = match bitness {
            Bitness::X86 => 4,
            Bitness::X64 => 8,
        };
        let mut keys = Vec::new();

        // Read all 256 dispatch table entries
        for opcode in 0..=255u8 {
            let entry_va = dispatch_table_va + (opcode as u64 * entry_size);

            let entry_read = match bitness {
                Bitness::X86 => binary.read_u32(entry_va).map(u64::from),
                Bitness::X64 => binary.read_u64(entry_va),
            };

            match entry_read {
                Ok(encrypted_addr) => {
                    // Extract the XOR key for this opcode
                    let key = Self::extract_key_for_entry(binary, opcode, encrypted_addr, image_base, bitness)?;

                    let decrypted = encrypted_addr ^ key;

                    keys.push(XorKeyEntry {
                        opcode,
                        key,
                        encrypted: encrypted_addr,
                        decrypted,
                    });
                }
                Err(_) => {
                    log::warn!("Failed to read dispatch table entry {}", opcode);
                    // Add placeholder entry
                    keys.push(XorKeyEntry {
                        opcode,
                        key: 0,
                        encrypted: 0,
                        decrypted: 0,
                    });
                }
            }
        }

        Ok(keys)
    }

    /// Extract XOR key for a specific dispatch table entry
    ///
    /// Uses pattern matching to find XOR instructions that populate
    /// the dispatch table with encrypted handler addresses.
    fn extract_key_for_entry(
        binary: &PEBinary,
        opcode: u8,
        encrypted_addr: u64,
        image_base: u64,
        bitness: Bitness,
    ) -> Result<u64> {
        // Strategy 1: Look for XOR instruction patterns in .text section
        if let Ok(text_data) = binary.get_section(".text") {
            if let Ok(key) = Self::find_xor_key_in_section(&text_data, opcode, encrypted_addr, image_base, bitness) {
                return Ok(key);
            }
        }

        // Strategy 2: Try common key patterns based on opcode
        let potential_keys = Self::generate_potential_keys(opcode);
        for key in potential_keys {
            let decrypted = encrypted_addr ^ key;

            // Check if decrypted address is in reasonable range
            if decrypted >= image_base && decrypted < image_base + 0x80000000 {
                return Ok(key);
            }
        }

        // Strategy 3: Use opcode-based key derivation
        // Many VMP versions use opcode as part of the key
        let opcode_key = Self::derive_opcode_key(opcode);
        let decrypted = encrypted_addr ^ opcode_key;
        if decrypted >= image_base && decrypted < image_base + 0x80000000 {
            return Ok(opcode_key);
        }

        // Fallback: return 0 (no encryption)
        Ok(0)
    }

    /// Find XOR key by scanning for XOR instruction patterns.
    ///
    /// Patterns are bitness-dependent:
    /// - x86-64 (`Bitness::X64`): `48 35 XX XX XX XX` (REX.W + XOR RAX, imm32)
    ///   and `48 81 F0 XX XX XX XX` (REX.W + XOR r/m64, imm32). Both
    ///   sign-extend the immediate to 64 bits per the Intel SDM.
    /// - x86 (`Bitness::X86`): the same encodings without the `0x48` REX
    ///   prefix — `35 XX XX XX XX` (XOR EAX, imm32) and `81 F0 XX XX XX XX`
    ///   (XOR EAX, imm32) — with the key taken as-is (`imm32 as u64`, no
    ///   sign-extension into the upper 32 bits, since x86 registers are
    ///   32-bit).
    fn find_xor_key_in_section(
        section_data: &[u8],
        opcode: u8,
        encrypted_addr: u64,
        image_base: u64,
        bitness: Bitness,
    ) -> Result<u64> {
        let patterns: &[XorPattern] = match bitness {
            Bitness::X64 => &[
                XorPattern {
                    prefix: &[0x48, 0x35],
                    sign_extend: true,
                },
                XorPattern {
                    prefix: &[0x48, 0x81, 0xF0],
                    sign_extend: true,
                },
            ],
            Bitness::X86 => &[
                XorPattern {
                    prefix: &[0x35],
                    sign_extend: false,
                },
                XorPattern {
                    prefix: &[0x81, 0xF0],
                    sign_extend: false,
                },
            ],
        };

        Self::scan_xor_patterns(section_data, patterns, encrypted_addr, image_base)
            .ok_or_else(|| anyhow::anyhow!("No XOR pattern found for opcode {}", opcode))
    }

    /// Shared pattern scanner used by [`Self::find_xor_key_in_section`] for
    /// both bitnesses: walks `section_data` looking for any of `patterns`
    /// followed by a 4-byte little-endian immediate, and returns the first
    /// key whose XOR-decrypted address falls in `[image_base, image_base +
    /// 0x8000_0000)`.
    fn scan_xor_patterns(
        section_data: &[u8],
        patterns: &[XorPattern],
        encrypted_addr: u64,
        image_base: u64,
    ) -> Option<u64> {
        for i in 0..section_data.len() {
            for pattern in patterns {
                let prefix_len = pattern.prefix.len();
                let imm_start = i + prefix_len;
                let imm_end = imm_start + 4;
                if imm_end > section_data.len() {
                    continue;
                }
                if &section_data[i..imm_start] != pattern.prefix {
                    continue;
                }

                let imm32 = u32::from_le_bytes([
                    section_data[imm_start],
                    section_data[imm_start + 1],
                    section_data[imm_start + 2],
                    section_data[imm_start + 3],
                ]);

                let key = if pattern.sign_extend {
                    (imm32 as i32) as i64 as u64
                } else {
                    imm32 as u64
                };

                let decrypted = encrypted_addr ^ key;
                if decrypted >= image_base && decrypted < image_base + 0x80000000 {
                    return Some(key);
                }
            }
        }

        None
    }

    /// Generate potential XOR keys based on opcode
    fn generate_potential_keys(opcode: u8) -> Vec<u64> {
        vec![
            0x0000000000000000u64,
            0xFFFFFFFFFFFFFFFFu64,
            opcode as u64,
            ((opcode as u64) << 8) | (opcode as u64),
            ((opcode as u64) << 16) | ((opcode as u64) << 8) | (opcode as u64),
            ((opcode as u64) << 24) | ((opcode as u64) << 16) | ((opcode as u64) << 8) | (opcode as u64),
            ((opcode as u64) << 32)
                | ((opcode as u64) << 24)
                | ((opcode as u64) << 16)
                | ((opcode as u64) << 8)
                | (opcode as u64),
            (opcode as u64).wrapping_mul(0x0101010101010101),
            (opcode as u64).wrapping_mul(0x0202020202020202),
            (opcode as u64).wrapping_mul(0x0404040404040404),
        ]
    }

    /// Derive XOR key from opcode using common VMP patterns
    fn derive_opcode_key(opcode: u8) -> u64 {
        // Common pattern: replicate opcode across all bytes
        let byte = opcode as u64;
        (byte << 56) | (byte << 48) | (byte << 40) | (byte << 32) | (byte << 24) | (byte << 16) | (byte << 8) | byte
    }

    /// Validate extracted keys
    pub fn validate_keys(keys: &[XorKeyEntry], image_base: u64) -> Result<bool> {
        let mut valid_count = 0;
        let mut zero_count = 0;

        for entry in keys {
            if entry.key == 0 && entry.encrypted == 0 {
                zero_count += 1;
                continue;
            }

            // Check if decrypted address is in reasonable range
            if entry.decrypted >= image_base && entry.decrypted < image_base + 0x80000000 {
                valid_count += 1;
            }
        }

        // At least 200 out of 256 should be valid (excluding zero entries)
        let is_valid = valid_count >= 200;
        log::info!(
            "Key validation: {}/{} valid keys ({} zero entries)",
            valid_count,
            keys.len() - zero_count,
            zero_count
        );

        Ok(is_valid)
    }

    /// Get decrypted handler addresses from keys
    pub fn get_handler_addresses(keys: &[XorKeyEntry]) -> Vec<u64> {
        keys.iter().map(|k| k.decrypted).collect()
    }

    /// Export keys to JSON
    pub fn export_keys_json(keys: &[XorKeyEntry], path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(&keys).context("Failed to serialize keys")?;
        std::fs::write(path, json).context("Failed to write keys file")?;
        log::info!("Keys exported to: {}", path);
        Ok(())
    }

    /// Get statistics about extracted keys
    pub fn get_key_statistics(keys: &[XorKeyEntry]) -> KeyStatistics {
        let mut unique_keys = std::collections::HashSet::new();
        let mut valid_count = 0;
        let mut zero_count = 0;

        for entry in keys {
            if entry.key == 0 {
                zero_count += 1;
            } else {
                unique_keys.insert(entry.key);
                valid_count += 1;
            }
        }

        KeyStatistics {
            total_entries: keys.len(),
            valid_entries: valid_count,
            zero_entries: zero_count,
            unique_keys: unique_keys.len(),
        }
    }
}

/// Statistics about extracted keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStatistics {
    /// Total number of entries
    pub total_entries: usize,
    /// Number of valid (non-zero) entries
    pub valid_entries: usize,
    /// Number of zero entries
    pub zero_entries: usize,
    /// Number of unique key values
    pub unique_keys: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulator_creation() {
        let emulator = XorKeyAnalyzer::new(0x48138, 0x400000);
        assert_eq!(emulator.dispatch_table_va, 0x48138);
        assert_eq!(emulator.image_base, 0x400000);
    }

    #[test]
    fn test_opcode_key_derivation() {
        let key = XorKeyAnalyzer::derive_opcode_key(0x42);
        assert_eq!(key, 0x4242424242424242u64);
    }

    #[test]
    fn test_potential_keys_generation() {
        let keys = XorKeyAnalyzer::generate_potential_keys(0xFF);
        assert!(!keys.is_empty());
        assert!(keys.contains(&0xFFFFFFFFFFFFFFFFu64));
    }

    #[test]
    fn find_xor_key_x86_35_pattern_matches() {
        let image_base = 0x0040_0000u64;
        let decrypted = image_base + 0x1000;
        let key: u64 = 0x1122_3344;
        let encrypted = decrypted ^ key;

        let mut section = vec![0x90u8; 4]; // filler
        section.push(0x35); // XOR EAX, imm32
        section.extend_from_slice(&(key as u32).to_le_bytes());

        let found = XorKeyAnalyzer::find_xor_key_in_section(&section, 0, encrypted, image_base, Bitness::X86)
            .expect("x86 35-pattern should be found");
        assert_eq!(found, key);
    }

    #[test]
    fn find_xor_key_x86_81f0_pattern_matches() {
        let image_base = 0x0040_0000u64;
        let decrypted = image_base + 0x2000;
        let key: u64 = 0x0000_ABCD;
        let encrypted = decrypted ^ key;

        let mut section = vec![0x90u8; 3]; // filler
        section.push(0x81);
        section.push(0xF0); // XOR EAX, imm32
        section.extend_from_slice(&(key as u32).to_le_bytes());

        let found = XorKeyAnalyzer::find_xor_key_in_section(&section, 1, encrypted, image_base, Bitness::X86)
            .expect("x86 81 F0-pattern should be found");
        assert_eq!(found, key);
    }

    #[test]
    fn find_xor_key_x86_no_sign_extension_into_upper_bits() {
        // imm32 with the high bit set must NOT be sign-extended for x86 —
        // the key stays within the low 32 bits.
        let image_base = 0x0040_0000u64;
        let imm32: u32 = 0x8000_0001;
        let key = imm32 as u64;
        let decrypted = image_base + 0x3000;
        let encrypted = decrypted ^ key;

        let mut section = vec![0x35];
        section.extend_from_slice(&imm32.to_le_bytes());

        let found = XorKeyAnalyzer::find_xor_key_in_section(&section, 2, encrypted, image_base, Bitness::X86)
            .expect("pattern should be found");
        assert_eq!(found, imm32 as u64);
        assert_eq!(found >> 32, 0, "x86 key must not carry bits above bit 31");
    }

    #[test]
    fn find_xor_key_x86_rejects_when_decrypt_out_of_range() {
        let image_base = 0x0040_0000u64;
        // encrypted_addr chosen so XOR-ing with the only candidate key in
        // the section never lands inside [image_base, image_base + 0x8000_0000).
        let key: u64 = 0x1234_5678;
        let encrypted = 0xFFFF_FFFFu64 ^ key; // decrypts to 0xFFFFFFFF, out of range

        let mut section = vec![0x35];
        section.extend_from_slice(&(key as u32).to_le_bytes());

        let result = XorKeyAnalyzer::find_xor_key_in_section(&section, 3, encrypted, image_base, Bitness::X86);
        assert!(result.is_err());
    }

    #[test]
    fn find_xor_key_x64_48_35_pattern_sign_extends() {
        let image_base = 0x1_4000_0000u64;
        let decrypted = image_base + 0x2000;
        let imm32: u32 = 0xFFFF_FF10; // high bit set -> sign-extends on x64
        let key = (imm32 as i32) as i64 as u64;
        let encrypted = decrypted ^ key;

        let mut section = vec![0x48, 0x35];
        section.extend_from_slice(&imm32.to_le_bytes());

        let found = XorKeyAnalyzer::find_xor_key_in_section(&section, 4, encrypted, image_base, Bitness::X64)
            .expect("x64 48 35-pattern should be found");
        assert_eq!(found, key);
    }
}
