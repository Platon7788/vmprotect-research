//! Operand Decryption
//!
//! CRC-based operand decryption for VMP bytecode.

/// Opcode cryptor for operand decryption
pub struct OpcodeCryptor {
    crc_value: u64,
}

impl OpcodeCryptor {
    /// Create new cryptor
    pub fn new() -> Self {
        OpcodeCryptor { crc_value: 0 }
    }

    /// Initialize CRC from section start address
    pub fn init_from_section(&mut self, start_vip: u64) {
        self.crc_value = start_vip;
    }

    /// Decrypt operand byte using current CRC state
    pub fn decrypt_operand(&self, encrypted_byte: u8, _cryptor_size: usize) -> u8 {
        let crc_low = (self.crc_value & 0xFF) as u8;
        encrypted_byte ^ crc_low
    }

    /// Update CRC after reading operand
    pub fn update_crc(&mut self, operand_value: u8) {
        self.crc_value = self.crc_value.wrapping_mul(31).wrapping_add(operand_value as u64);
    }

    /// Decrypt operand sequence (1/2/4/8 bytes)
    pub fn decrypt_operands(&mut self, encrypted: &[u8]) -> Vec<u8> {
        let mut decrypted = Vec::new();

        for &byte in encrypted {
            let dec = self.decrypt_operand(byte, 1);
            decrypted.push(dec);
            self.update_crc(dec);
        }

        decrypted
    }

    /// Decrypt u32 value (little-endian)
    pub fn decrypt_value_u32(&mut self, encrypted: &[u8; 4]) -> u32 {
        let decrypted = self.decrypt_operands(encrypted);
        u32::from_le_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]])
    }

    /// Decrypt u64 value (little-endian)
    pub fn decrypt_value_u64(&mut self, encrypted: &[u8; 8]) -> u64 {
        let decrypted = self.decrypt_operands(encrypted);
        u64::from_le_bytes([
            decrypted[0],
            decrypted[1],
            decrypted[2],
            decrypted[3],
            decrypted[4],
            decrypted[5],
            decrypted[6],
            decrypted[7],
        ])
    }

    /// Get current CRC value
    pub fn get_crc(&self) -> u64 {
        self.crc_value
    }

    /// Set CRC value
    pub fn set_crc(&mut self, value: u64) {
        self.crc_value = value;
    }
}

impl Default for OpcodeCryptor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_operand() {
        let mut cryptor = OpcodeCryptor::new();
        cryptor.set_crc(0xDEAD_BEEFu64);
        let encrypted = 0x42u8;
        let decrypted = cryptor.decrypt_operand(encrypted, 1);

        // XOR with low byte of CRC (0xEF): 0x42 ^ 0xEF = 0xAD
        assert_eq!(decrypted, 0x42 ^ 0xEF);
    }

    #[test]
    fn test_crc_update_matches_documented_formula() {
        // Pin down the exact `crc * 31 + val` recurrence — the earlier
        // `assert_ne!(after, before)` accepted any monotonic-ish update
        // (e.g. `crc + val`, `crc ^ val`) as valid, letting a formula
        // regression silently corrupt every downstream operand decode.
        let mut cryptor = OpcodeCryptor::new();
        cryptor.set_crc(0);

        cryptor.update_crc(0x11);
        assert_eq!(cryptor.get_crc(), 0u64.wrapping_mul(31).wrapping_add(0x11));

        cryptor.update_crc(0x22);
        assert_eq!(cryptor.get_crc(), 0x11u64.wrapping_mul(31).wrapping_add(0x22));

        cryptor.update_crc(0x33);
        let expected_after_third = 0x11u64
            .wrapping_mul(31)
            .wrapping_add(0x22)
            .wrapping_mul(31)
            .wrapping_add(0x33);
        assert_eq!(cryptor.get_crc(), expected_after_third);
    }

    /// A u32 round-trip: encrypt bytes locally (mirroring the decrypt +
    /// update_crc cycle), then decrypt via the public API and assert both
    /// the returned value and the resulting cryptor state.
    #[test]
    fn decrypt_value_u32_round_trip() {
        let plaintext: u32 = 0xDEAD_BEEF;
        let plain_bytes = plaintext.to_le_bytes();
        let mut mirror_crc: u64 = 0x1234_5678;
        let mut encrypted = [0u8; 4];
        for (i, &b) in plain_bytes.iter().enumerate() {
            encrypted[i] = b ^ (mirror_crc as u8);
            mirror_crc = mirror_crc.wrapping_mul(31).wrapping_add(b as u64);
        }

        let mut cryptor = OpcodeCryptor::new();
        cryptor.set_crc(0x1234_5678);
        let decoded = cryptor.decrypt_value_u32(&encrypted);

        assert_eq!(decoded, plaintext);
        assert_eq!(cryptor.get_crc(), mirror_crc);
    }

    /// Same idea for u64 — guards `decrypt_value_u64`'s from_le_bytes
    /// assembly against endianness / index mistakes.
    #[test]
    fn decrypt_value_u64_round_trip() {
        let plaintext: u64 = 0xCAFE_BABE_DEAD_BEEF;
        let plain_bytes = plaintext.to_le_bytes();
        let mut mirror_crc: u64 = 0xA5A5_A5A5;
        let mut encrypted = [0u8; 8];
        for (i, &b) in plain_bytes.iter().enumerate() {
            encrypted[i] = b ^ (mirror_crc as u8);
            mirror_crc = mirror_crc.wrapping_mul(31).wrapping_add(b as u64);
        }

        let mut cryptor = OpcodeCryptor::new();
        cryptor.set_crc(0xA5A5_A5A5);
        let decoded = cryptor.decrypt_value_u64(&encrypted);

        assert_eq!(decoded, plaintext);
        assert_eq!(cryptor.get_crc(), mirror_crc);
    }
}
