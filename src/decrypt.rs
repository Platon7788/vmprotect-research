//! Operand Decryption
//!
//! VMProtect encrypts every operand byte in the bytecode stream with a
//! per-version cipher. Historically this crate shipped a single
//! [`OpcodeCryptor`] with a `crc = crc * 31 + val` recurrence that is not
//! mapped to any published VMP version — see the `Placeholder` variant.
//!
//! Commit M replaces that with a [`CryptoScheme`] enum backed by three
//! reverse-engineered shapes, extracted from public write-ups (no code
//! copied from GPL projects — see individual variant doc comments for
//! the source URL). Every choice below is BEST-EFFORT: the per-build
//! transform lists in real VMP 2.x/3.x are randomised, and validation
//! against real samples remains open (AUDIT_REPORT.md §Q4 Days 6-7,
//! blocked on VMP-protected fixture availability).
//!
//! The `OpcodeCryptor` public API is stable: `decrypt_operand`,
//! `update_crc`, `init_from_section`, `decrypt_operands`,
//! `decrypt_value_u32`, `decrypt_value_u64`, `get_crc`, `set_crc` all
//! keep their old signatures so existing callers (`Bytecode::read_imm`)
//! continue to work without change. `new()` still defaults to the
//! Placeholder scheme; the new [`OpcodeCryptor::new_with_scheme`]
//! constructor is the preferred entry point going forward.

use crate::VmpVersion;

/// Cryptographic scheme VMProtect uses to encrypt operand bytes.
///
/// Distinct per major version. Selection for a detected version is
/// delegated to [`CryptoScheme::for_version`]; the pipeline in
/// `VmpDevirtualizer::devirtualize_range` calls it once per range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoScheme {
    /// No cryptor (VMP 1.x — the operand bytes in VMP1's bytecode
    /// stream are not protected by a running stream cipher, per the
    /// public write-ups; the per-version cryptor is a VMP 2.x-onwards
    /// construct).
    None,
    /// Historical `crc = crc * 31 + val` recurrence unmapped to any
    /// documented VMP version. Retained as the default so existing
    /// callers that instantiate `OpcodeCryptor::new()` keep their
    /// behaviour.
    Placeholder,
    /// VMProtect 2.x rolling arithmetic chain (BEST-EFFORT reconstruction).
    ///
    /// Source: back.engineering "VMProtect 2 - Detailed Analysis of the
    /// Virtual Machine Architecture" (2021-05-17) — accessed via the
    /// gmh5225 GitHub mirror because back.engineering serves 403 to
    /// non-browser clients. Key quote: "rolling decryption key is
    /// started in RBX and is used to decrypt every single operand …
    /// initially set to the address of the virtual instructions".
    ///
    /// Real builds randomise the exact 5-step chain (rolling-key op +
    /// 3 generic transforms + key update); this variant applies a
    /// single documented choice — XOR-key, NEG, ROL 5, INC — so the
    /// implementation is invertible and cross-check-able. Validation
    /// against real samples remains open.
    Vmp2Rolling,
    /// VMProtect 3.x per-handler self-modifying cryptor (BEST-EFFORT).
    ///
    /// Source: r0da "VMProtect Analysis — Part 3 — Virtualization"
    /// (whereisr0da.github.io, 2021-02-16) and vxcall "VMProtect 3.8.1"
    /// (2024). Both describe a rolling key in a per-instance GPR
    /// (`rdi` / `rbx` / `r9` / `rbp`) mutated by a chain baked into
    /// each handler's bytes (e.g. `xor al, bl; ror al, 1; dec al;
    /// not al; xor bl, al`).
    ///
    /// The concrete per-handler op selection requires cross-handler
    /// disassembly state we don't have yet, so this variant applies a
    /// DEFAULT op set (XOR-key, ROR 1, NOT) and logs the deviation.
    /// Real self-modifying dispatch is Commit K's register-role work.
    Vmp3PerHandler,
}

impl CryptoScheme {
    /// Recommended scheme for a given detected VMP version.
    ///
    /// `Unknown` falls back to `Placeholder` — the legacy behaviour —
    /// because we can't guess whether an unrecognised sample uses a
    /// VMP-2-shaped chain or a VMP-3-shaped one. Callers who know
    /// better can pass an explicit scheme via `new_with_scheme`.
    pub fn for_version(version: VmpVersion) -> Self {
        match version {
            VmpVersion::Vmp1 => CryptoScheme::None,
            VmpVersion::Vmp2 => CryptoScheme::Vmp2Rolling,
            VmpVersion::Vmp30 | VmpVersion::Vmp35 | VmpVersion::Vmp36Plus => CryptoScheme::Vmp3PerHandler,
            VmpVersion::Unknown => CryptoScheme::Placeholder,
        }
    }

    /// Stable string name for each variant, used by the unified
    /// analysis-export (Commit R) so the scheme choice JSON-serialises
    /// as a plain string instead of requiring `CryptoScheme` itself to
    /// derive `serde::Serialize` (which would expose the internal
    /// variant names as a public wire format).
    pub fn as_str(&self) -> &'static str {
        match self {
            CryptoScheme::None => "None",
            CryptoScheme::Placeholder => "Placeholder",
            CryptoScheme::Vmp2Rolling => "Vmp2Rolling",
            CryptoScheme::Vmp3PerHandler => "Vmp3PerHandler",
        }
    }
}

/// Internal state carrier — one variant per [`CryptoScheme`].
///
/// Kept out of the public API because the field names are per-scheme
/// implementation detail and would leak the choice to callers.
#[derive(Debug, Clone, Copy)]
enum CryptoState {
    None,
    Placeholder { crc: u64 },
    Vmp2Rolling { key: u64 },
    Vmp3PerHandler { key: u64 },
}

/// Opcode cryptor for operand decryption.
///
/// Same public methods as before Commit M — new backends plug in via
/// [`CryptoScheme`] without breaking `Bytecode::read_imm`.
pub struct OpcodeCryptor {
    scheme: CryptoScheme,
    state: CryptoState,
}

impl OpcodeCryptor {
    /// Legacy constructor — Placeholder scheme, `crc = 0`. Kept so the
    /// pre-Commit-M call sites (and the existing round-trip tests that
    /// pin `crc*31+val` behaviour) keep working unchanged.
    pub fn new() -> Self {
        Self::new_with_scheme(CryptoScheme::Placeholder)
    }

    /// Preferred constructor — pick the scheme up front, typically via
    /// [`CryptoScheme::for_version`].
    pub fn new_with_scheme(scheme: CryptoScheme) -> Self {
        let state = match scheme {
            CryptoScheme::None => CryptoState::None,
            CryptoScheme::Placeholder => CryptoState::Placeholder { crc: 0 },
            CryptoScheme::Vmp2Rolling => CryptoState::Vmp2Rolling { key: 0 },
            CryptoScheme::Vmp3PerHandler => CryptoState::Vmp3PerHandler { key: 0 },
        };
        OpcodeCryptor { scheme, state }
    }

    /// The [`CryptoScheme`] this cryptor was built for. Exposed for
    /// audit-trail logging in `devirtualize_range`.
    pub fn scheme(&self) -> CryptoScheme {
        self.scheme
    }

    /// Initialize the running key from a section-start VIP address.
    ///
    /// For every non-`None` scheme this seeds the same slot `set_crc`
    /// writes, matching the write-ups' "first value loaded into RBX is
    /// the address of the virtual instructions".
    pub fn init_from_section(&mut self, start_vip: u64) {
        match &mut self.state {
            CryptoState::None => {}
            CryptoState::Placeholder { crc } => *crc = start_vip,
            CryptoState::Vmp2Rolling { key } => *key = start_vip,
            CryptoState::Vmp3PerHandler { key } => *key = start_vip,
        }
    }

    /// Decrypt one operand byte against the current state — does NOT
    /// advance it (state advancement is the caller's job via
    /// `update_crc(plaintext)`, so `Bytecode::read_imm`'s existing
    /// read → decrypt → assemble → advance loop stays intact).
    ///
    /// `_cryptor_size` is legacy — the byte-at-a-time contract has
    /// always been true, and the parameter is preserved for API
    /// stability only.
    pub fn decrypt_operand(&self, encrypted_byte: u8, _cryptor_size: usize) -> u8 {
        match &self.state {
            CryptoState::None => encrypted_byte,
            CryptoState::Placeholder { crc } => encrypted_byte ^ ((crc & 0xFF) as u8),
            CryptoState::Vmp2Rolling { key } => {
                // Concrete example from back.engineering VMP 2 write-up:
                //   xor al, bl ; neg al ; rol al, 5 ; inc al ; xor bl, al
                // Steps 1-4 belong here; step 5 is `update_crc`.
                let p = encrypted_byte ^ ((key & 0xFF) as u8);
                let p = p.wrapping_neg();
                let p = p.rotate_left(5);
                p.wrapping_add(1)
            }
            CryptoState::Vmp3PerHandler { key } => {
                // Concrete example from r0da VMP-3 Part 3:
                //   xor al, bl ; ror al, 1 ; dec al ; not al ; dec al ; xor bl, al
                // We ship the minimal invertible subset (XOR-key, ROR 1,
                // NOT); the two `dec` steps are per-build randomised
                // and would need per-handler disassembly (Commit K) to
                // recover accurately.
                let p = encrypted_byte ^ ((key & 0xFF) as u8);
                let p = p.rotate_right(1);
                !p
            }
        }
    }

    /// Advance the running state using the just-decrypted plaintext byte.
    ///
    /// Named `update_crc` for API stability — the "CRC" label predates
    /// the per-scheme dispatch and now covers whatever running-state
    /// slot the current scheme carries.
    pub fn update_crc(&mut self, operand_value: u8) {
        match &mut self.state {
            CryptoState::None => {}
            CryptoState::Placeholder { crc } => {
                *crc = crc.wrapping_mul(31).wrapping_add(operand_value as u64);
            }
            CryptoState::Vmp2Rolling { key } => {
                // "The rolling decryption key is updated by transforming
                // it with the decrypted operand value" — back.engineering
                // VMP 2. Documented op set includes XOR / ADD / SUB /
                // ROL / ROR / AND; XOR is picked as the invertible
                // default and matches the concrete `xor bl, al` example.
                *key ^= operand_value as u64;
            }
            CryptoState::Vmp3PerHandler { key } => {
                // vxcall VMProtect 3.8.1: "Each decryption completes
                // with `xor rdi, [decrypted_value]` to update the
                // rolling key for the next handler."
                *key ^= operand_value as u64;
            }
        }
    }

    /// Decrypt operand sequence (1/2/4/8 bytes).
    pub fn decrypt_operands(&mut self, encrypted: &[u8]) -> Vec<u8> {
        let mut decrypted = Vec::with_capacity(encrypted.len());
        for &byte in encrypted {
            let dec = self.decrypt_operand(byte, 1);
            decrypted.push(dec);
            self.update_crc(dec);
        }
        decrypted
    }

    /// Decrypt u32 value (little-endian).
    pub fn decrypt_value_u32(&mut self, encrypted: &[u8; 4]) -> u32 {
        let decrypted = self.decrypt_operands(encrypted);
        u32::from_le_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]])
    }

    /// Decrypt u64 value (little-endian).
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

    /// Get current running-state value (the "CRC" label is legacy —
    /// see `update_crc`).
    pub fn get_crc(&self) -> u64 {
        match &self.state {
            CryptoState::None => 0,
            CryptoState::Placeholder { crc } => *crc,
            CryptoState::Vmp2Rolling { key } => *key,
            CryptoState::Vmp3PerHandler { key } => *key,
        }
    }

    /// Set running-state value. No-op for `CryptoScheme::None`.
    pub fn set_crc(&mut self, value: u64) {
        match &mut self.state {
            CryptoState::None => {}
            CryptoState::Placeholder { crc } => *crc = value,
            CryptoState::Vmp2Rolling { key } => *key = value,
            CryptoState::Vmp3PerHandler { key } => *key = value,
        }
    }
}

impl Default for OpcodeCryptor {
    fn default() -> Self {
        Self::new()
    }
}

// Test module split out to keep this file under the 500-line project cap;
// the whole tests block lives in `decrypt_tests.rs` and is folded in via
// `#[path]` so the file layout still looks flat.
#[cfg(test)]
#[path = "decrypt_tests.rs"]
mod tests;
