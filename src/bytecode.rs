//! Bytecode Decoder
//!
//! Parses VMP bytecode instructions.

use crate::{Handler, OpcodeCryptor, PEBinary};
use anyhow::{Context, Result};

// Handler name constants, shared between operand decoding and size computation.
const H_PUSH_REG: &str = "PUSH_REG";
const H_PUSH_VALUE: &str = "PUSH_VALUE";
const H_POP_MEMORY: &str = "POP_MEMORY";
const H_ADD_REG: &str = "ADD_REG";
const H_SUB_REG: &str = "SUB_REG";
const H_XOR_REG: &str = "XOR_REG";
const H_OR_REG: &str = "OR_REG";
const H_AND_REG: &str = "AND_REG";
const H_NOR_CHAIN: &str = "NOR_CHAIN";
const H_NAND_CHAIN: &str = "NAND_CHAIN";
const H_JMP: &str = "JMP";
const H_RET: &str = "RET";

/// Bytecode instruction
pub struct Bytecode {
    data: Vec<u8>,
    vip: u64,
}

impl Bytecode {
    /// Load bytecode from VIP address
    pub fn from_vip(binary: &PEBinary, vip: u64) -> Result<Self> {
        // Read max 256 bytes (longest instruction + operands)
        let data = binary.read_bytes(vip, 256)?;

        Ok(Bytecode { data, vip })
    }

    /// Get opcode byte (at offset 0 for vtBasic)
    pub fn opcode_byte(&self) -> u8 {
        self.data.first().copied().unwrap_or(0)
    }

    /// Decode operands based on handler type.
    ///
    /// `cryptor` carries the CRC state forward across handlers within a
    /// single `devirtualize_range` call — VMP's operand cipher is a running
    /// stream cipher over the whole bytecode section, not reset per
    /// instruction, so the caller must reuse the same `OpcodeCryptor`
    /// instance for every instruction it decodes in sequence.
    pub fn decode_operands(&self, handler: &Handler, cryptor: &mut OpcodeCryptor) -> Result<Vec<u64>> {
        let mut operands = Vec::new();

        match handler.name.as_str() {
            H_PUSH_REG => {
                // 1 byte: register ID
                operands.push(self.read_imm(1, 1, cryptor)?);
            }
            H_PUSH_VALUE => {
                // Variable: 1/2/4/8 bytes immediate
                if let Some(size) = handler.size_bytes {
                    if size > 1 {
                        let imm_size = size - 1;
                        let imm = self.read_imm(1, imm_size, cryptor)?;
                        operands.push(imm);
                    }
                }
            }
            H_POP_MEMORY => {
                // Memory offset encoding
                operands.push(self.read_imm(1, 1, cryptor)?);
            }
            H_ADD_REG | H_SUB_REG | H_XOR_REG | H_OR_REG | H_AND_REG => {
                // Stack-based, no operand bytes
            }
            H_NOR_CHAIN | H_NAND_CHAIN => {
                // Chain data: no operand bytes are read here today (the
                // handler carries no immediate beyond its opcode slot in
                // this decoder), so there is nothing to route through the
                // cryptor yet. See AUDIT_REPORT.md Q4 — extending this to
                // consume/decrypt trailing chain bytes is separate scope.
                operands.push(self.vip);
            }
            H_JMP => {
                // Jump target
                let offset = self.read_imm(1, 4, cryptor)?;
                operands.push((self.vip as i64 + offset as i64) as u64);
            }
            H_RET => {
                // No operands
            }
            _ => {
                // Unknown handler
            }
        }

        Ok(operands)
    }

    /// Read an immediate value from bytecode, decrypting each byte through
    /// `cryptor` before assembling it (little-endian).
    ///
    /// This is the single choke point where raw operand bytes become
    /// interpreted values, so it is where `OpcodeCryptor` is applied: every
    /// operand read advances the cryptor's CRC state via `update_crc`,
    /// matching VMP's stream-cipher-like behavior where each decrypted byte
    /// feeds the state used to decrypt the next one.
    fn read_imm(&self, offset: usize, size: usize, cryptor: &mut OpcodeCryptor) -> Result<u64> {
        let bytes = self
            .data
            .get(offset..offset + size)
            .context(format!("Cannot read {} bytes at offset {}", size, offset))?;

        let mut value: u64 = 0;
        for (i, &b) in bytes.iter().enumerate() {
            let decrypted = cryptor.decrypt_operand(b, 1);
            cryptor.update_crc(decrypted);
            value |= (decrypted as u64) << (i * 8);
        }

        Ok(value)
    }

    /// Size of this instruction in bytes: 1 opcode slot byte + operand bytes.
    ///
    /// The operand layout is handler-dependent; see `operand_bytes` for the
    /// per-handler rules. Handlers that cannot be sized (unknown/invalid or
    /// unrecognized names) return an error rather than a guessed size.
    pub fn size(&self, handler: &Handler) -> Result<usize> {
        Ok(1 + operand_bytes(handler)?)
    }

    /// Get VIP address
    pub fn vip(&self) -> u64 {
        self.vip
    }

    /// Get raw bytecode data
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Number of operand bytes following the opcode slot byte, per handler type.
///
/// Fixed-layout handlers use a hardcoded byte count. Variable-length handlers
/// (`PUSH_VALUE`, `NOR_CHAIN`, `NAND_CHAIN`) use `handler.size_bytes` as the
/// authoritative full instruction length (opcode + operands), so the operand
/// count is `size_bytes - 1`. Unknown/unrecognized handlers are an error.
fn operand_bytes(handler: &Handler) -> Result<usize> {
    match handler.name.as_str() {
        H_PUSH_REG | H_POP_MEMORY => Ok(1),
        H_ADD_REG | H_SUB_REG | H_XOR_REG | H_OR_REG | H_AND_REG | H_RET => Ok(0),
        H_JMP => Ok(4),
        H_PUSH_VALUE | H_NOR_CHAIN | H_NAND_CHAIN => {
            let full_size = handler
                .size_bytes
                .context(format!("handler '{}' has no size_bytes hint", handler.name))?;
            full_size.checked_sub(1).context(format!(
                "handler '{}' has invalid size_bytes: {}",
                handler.name, full_size
            ))
        }
        _ => Err(anyhow::anyhow!("cannot determine size for handler '{}'", handler.name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_byte() {
        let bytecode = Bytecode {
            data: vec![0x11, 0x05, 0x00, 0x00],
            vip: 0x140001000,
        };

        assert_eq!(bytecode.opcode_byte(), 0x11);
    }

    fn make_bytecode() -> Bytecode {
        Bytecode {
            data: vec![0x00; 16],
            vip: 0x140001000,
        }
    }

    fn make_handler(name: &str, size_bytes: Option<usize>) -> Handler {
        Handler {
            name: name.to_string(),
            opcode: 0x11,
            size_bytes,
        }
    }

    #[test]
    fn test_size_ret_is_one() {
        let bytecode = make_bytecode();
        let handler = make_handler(H_RET, None);
        assert_eq!(bytecode.size(&handler).unwrap(), 1);
    }

    #[test]
    fn test_size_add_reg_is_one() {
        let bytecode = make_bytecode();
        let handler = make_handler(H_ADD_REG, None);
        assert_eq!(bytecode.size(&handler).unwrap(), 1);
    }

    #[test]
    fn test_size_push_reg_is_two() {
        let bytecode = make_bytecode();
        let handler = make_handler(H_PUSH_REG, None);
        assert_eq!(bytecode.size(&handler).unwrap(), 2);
    }

    #[test]
    fn test_size_pop_memory_is_two() {
        let bytecode = make_bytecode();
        let handler = make_handler(H_POP_MEMORY, None);
        assert_eq!(bytecode.size(&handler).unwrap(), 2);
    }

    #[test]
    fn test_size_jmp_is_five() {
        let bytecode = make_bytecode();
        let handler = make_handler(H_JMP, None);
        assert_eq!(bytecode.size(&handler).unwrap(), 5);
    }

    #[test]
    fn test_size_push_value_uses_size_bytes_hint() {
        let bytecode = make_bytecode();
        let handler = make_handler(H_PUSH_VALUE, Some(5));
        assert_eq!(bytecode.size(&handler).unwrap(), 5);
    }

    #[test]
    fn test_size_push_value_without_hint_errors() {
        let bytecode = make_bytecode();
        let handler = make_handler(H_PUSH_VALUE, None);
        assert!(bytecode.size(&handler).is_err());
    }

    #[test]
    fn test_size_unknown_handler_errors() {
        let bytecode = make_bytecode();
        let handler = make_handler("UNKNOWN", None);
        assert!(bytecode.size(&handler).is_err());
    }

    #[test]
    fn test_size_invalid_handler_errors() {
        let bytecode = make_bytecode();
        let handler = make_handler("INVALID", None);
        assert!(bytecode.size(&handler).is_err());
    }

    #[test]
    fn test_decode_operands_applies_cryptor_decryption() {
        // Same encrypted bytes, two different cryptor CRC states: the
        // decoded operand value must differ, proving decode_operands routes
        // bytes through the cryptor instead of interpreting them raw.
        let bytecode = Bytecode {
            data: vec![0x11, 0xAB, 0xCD, 0x00, 0x00],
            vip: 0x140001000,
        };
        let handler = make_handler(H_PUSH_VALUE, Some(5));

        let mut zero_crc = OpcodeCryptor::new();
        zero_crc.set_crc(0);
        let with_zero_crc = bytecode.decode_operands(&handler, &mut zero_crc).unwrap();

        let mut nonzero_crc = OpcodeCryptor::new();
        nonzero_crc.set_crc(0x55);
        let with_nonzero_crc = bytecode.decode_operands(&handler, &mut nonzero_crc).unwrap();

        assert_ne!(with_zero_crc, with_nonzero_crc);
    }

    #[test]
    fn test_decode_operands_advances_cryptor_state() {
        // The cryptor's CRC must change after decoding an operand so the
        // next handler in the stream sees a different key, matching VMP's
        // running-cipher behavior across a bytecode section.
        let bytecode = Bytecode {
            data: vec![0x11, 0xAB, 0x00, 0x00, 0x00],
            vip: 0x140001000,
        };
        let handler = make_handler(H_PUSH_REG, None);

        let mut cryptor = OpcodeCryptor::new();
        let crc_before = cryptor.get_crc();
        bytecode.decode_operands(&handler, &mut cryptor).unwrap();

        assert_ne!(cryptor.get_crc(), crc_before);
    }
}
