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
                // Jump target. `read_imm` returns the 4-byte immediate zero-
                // extended in a u64, so a negative rel32 (e.g. 0xFFFFFF00)
                // would land at +4_294_967_040 instead of -256 if fed
                // straight into i64 arithmetic. Cast through i32 to preserve
                // the sign for backward jumps.
                let raw = self.read_imm(1, 4, cryptor)?;
                let offset = raw as u32 as i32;
                operands.push((self.vip as i64).wrapping_add(offset as i64) as u64);
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
        // Cap at u64's width: the assembly loop below shifts by `i * 8`, so
        // `size == 9` would compute `(byte as u64) << 64` — an overflow that
        // panics in debug and is undefined behaviour in release. VMP operands
        // are 1/2/4/8 bytes; anything larger is a bogus handler table.
        if size > 8 {
            anyhow::bail!("read_imm size {} exceeds u64 width (max 8)", size);
        }

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

    /// `operand_bytes`'s `_` wildcard covers every handler name outside
    /// the known family constants; `"UNKNOWN"` and `"INVALID"` both hit
    /// the same arm. Previously these were two identical tests.
    #[test]
    fn test_size_unrecognized_handler_errors() {
        let bytecode = make_bytecode();
        for name in ["UNKNOWN", "INVALID", "TOTALLY_NEW", ""] {
            let handler = make_handler(name, None);
            assert!(bytecode.size(&handler).is_err(), "handler {name:?} unexpectedly sized");
        }
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

    /// A negative rel32 (0xFFFFFF00 = -256) must decode as a backward jump
    /// (`vip - 256`), not the ~4 GB forward jump you'd get from a
    /// zero-extended `u32 -> i64` cast. Regression test for the bug the
    /// audit surfaced in `decode_operands`'s H_JMP arm.
    #[test]
    fn jmp_negative_rel32_produces_backward_target() {
        // Encrypted-byte-then-cryptor-invariance trick: feeding zero bytes
        // with an initial CRC of zero decrypts to zeros AND leaves the CRC
        // at zero (31*0 + 0 = 0), so a trailing 0xFF byte still XORs
        // against mask=0 and lands intact. The assembled little-endian
        // rel32 becomes 0xFF00_0000 -> i32 = -0x0100_0000. Without sign-
        // extension the H_JMP arm would treat this as +0xFF00_0000 and
        // produce vip + 4_278_190_080 instead of vip - 16_777_216.
        let vip: u64 = 0x140002000;
        let bytecode = Bytecode {
            data: vec![0x11, 0x00, 0x00, 0x00, 0xFF],
            vip,
        };
        let handler = make_handler(H_JMP, None);

        let mut cryptor = OpcodeCryptor::new();
        cryptor.set_crc(0);
        let operands = bytecode.decode_operands(&handler, &mut cryptor).unwrap();

        assert_eq!(operands.len(), 1);
        assert_eq!(operands[0], vip.wrapping_sub(0x0100_0000));
        assert!(operands[0] < vip, "backward jump must land before vip");
    }

    /// Positive-rel32 JMP still works after the sign-extension fix: a
    /// small positive delta must move forward from `vip`, not overflow.
    ///
    /// Encrypted bytes pre-computed so cryptor(CRC=0) decrypts them to
    /// the little-endian rel32 0x0000_0010 (= +16):
    ///   want decrypted[0..4] = [0x10, 0x00, 0x00, 0x00]
    ///   step 0: mask=0x00 -> enc=0x10, CRC := 31*0 + 0x10 = 0x10
    ///   step 1: mask=0x10 -> enc=0x00^0x10=0x10, CRC := 31*0x10 = 0x1F0
    ///   step 2: mask=0xF0 -> enc=0x00^0xF0=0xF0, CRC := 31*0x1F0 = 0x3C10
    ///   step 3: mask=0x10 -> enc=0x00^0x10=0x10
    #[test]
    fn jmp_positive_rel32_produces_forward_target() {
        let vip: u64 = 0x140002000;
        let bytecode = Bytecode {
            data: vec![0x11, 0x10, 0x10, 0xF0, 0x10],
            vip,
        };
        let handler = make_handler(H_JMP, None);

        let mut cryptor = OpcodeCryptor::new();
        cryptor.set_crc(0);
        let operands = bytecode.decode_operands(&handler, &mut cryptor).unwrap();

        assert_eq!(operands, vec![vip + 0x10]);
    }

    /// H_NOR_CHAIN / H_NAND_CHAIN currently emit `[vip]` as the sole
    /// operand and do NOT advance the cryptor (Q4 tracks routing chain
    /// bytes through the cryptor in a later change). Lock the current
    /// behaviour so an unintentional switch is visible in CI.
    #[test]
    fn nor_chain_operand_is_vip_and_leaves_cryptor_unchanged() {
        let vip: u64 = 0x140002000;
        let bytecode = Bytecode {
            data: vec![0x11, 0xAA, 0xBB, 0xCC],
            vip,
        };
        let handler = make_handler(H_NOR_CHAIN, Some(4));

        let mut cryptor = OpcodeCryptor::new();
        cryptor.set_crc(0xDEAD);
        let operands = bytecode.decode_operands(&handler, &mut cryptor).unwrap();

        assert_eq!(operands, vec![vip]);
        assert_eq!(cryptor.get_crc(), 0xDEAD, "chain handler must not advance CRC yet");
    }

    /// POP_MEMORY reads one operand byte through the cryptor. Regression
    /// against a change that would skip the cryptor for one-byte
    /// operands (which used to happen with a raw `self.data.get(1)`
    /// path before Days 4-5).
    #[test]
    fn pop_memory_routes_operand_byte_through_cryptor() {
        let bytecode = Bytecode {
            data: vec![0x11, 0x05, 0x00],
            vip: 0x140002000,
        };
        let handler = make_handler(H_POP_MEMORY, None);

        let mut cryptor_zero = OpcodeCryptor::new();
        cryptor_zero.set_crc(0);
        let with_zero = bytecode.decode_operands(&handler, &mut cryptor_zero).unwrap();

        let mut cryptor_ff = OpcodeCryptor::new();
        cryptor_ff.set_crc(0xFF);
        let with_ff = bytecode.decode_operands(&handler, &mut cryptor_ff).unwrap();

        // 0x05 XOR 0x00 = 0x05; 0x05 XOR 0xFF = 0xFA.
        assert_eq!(with_zero, vec![0x05]);
        assert_eq!(with_ff, vec![0xFA]);
    }

    /// Cryptor state must carry across handlers within a `devirtualize_range`
    /// call — Days 4-5's core design contract. A regression that
    /// re-seeded the cryptor per instruction would produce identical
    /// results here; the shared-cryptor path must differ from the
    /// fresh-cryptor path.
    #[test]
    fn cryptor_state_carries_across_sequential_decodes() {
        let handler = make_handler(H_PUSH_VALUE, Some(5));
        let bc = Bytecode {
            data: vec![0x11, 0x11, 0x22, 0x33, 0x44],
            vip: 0x140002000,
        };

        // Shared cryptor: state accumulates.
        let mut shared = OpcodeCryptor::new();
        shared.set_crc(0);
        let first_shared = bc.decode_operands(&handler, &mut shared).unwrap();
        let second_shared = bc.decode_operands(&handler, &mut shared).unwrap();

        // Fresh cryptor each call: state resets.
        let mut fresh_a = OpcodeCryptor::new();
        fresh_a.set_crc(0);
        let first_fresh = bc.decode_operands(&handler, &mut fresh_a).unwrap();

        let mut fresh_b = OpcodeCryptor::new();
        fresh_b.set_crc(0);
        let second_fresh = bc.decode_operands(&handler, &mut fresh_b).unwrap();

        // First call is identical (same initial state).
        assert_eq!(first_shared, first_fresh);
        // Second call MUST differ — proves the cryptor is stateful across handlers.
        assert_ne!(
            second_shared, second_fresh,
            "shared cryptor must diverge from fresh cryptor on the second decode"
        );
    }

    /// `read_imm` must refuse `size > 8` (the u64 width) instead of shift-
    /// overflow-panicking on the last iteration of its assembly loop.
    #[test]
    fn read_imm_rejects_size_beyond_u64_width() {
        // A crafted handler table (via `--export-opcodes` round-trip or
        // malformed JSON) could set size_bytes to 10; operand count then
        // becomes 9, which used to compute `(byte as u64) << 64` and panic
        // in debug builds.
        let bytecode = Bytecode {
            data: vec![0x11; 32],
            vip: 0x140001000,
        };
        let handler = make_handler(H_PUSH_VALUE, Some(10));

        let mut cryptor = OpcodeCryptor::new();
        let err = bytecode
            .decode_operands(&handler, &mut cryptor)
            .expect_err("size 9 must error, not panic");
        assert!(
            err.to_string().contains("exceeds u64 width"),
            "unexpected error message: {err}"
        );
    }
}
