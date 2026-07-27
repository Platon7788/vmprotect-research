//! Byte-level primitives shared by `handler_semantic.rs` and
//! `handler_semantic_ext.rs`.
//!
//! Split out of `handler_semantic.rs` via `#[path]` include so the
//! impl file stays under the project's 500-line ceiling (see
//! `CLAUDE.md`), same convention as `junk_stripper.rs` /
//! `junk_stripper_length.rs`. Re-exported into `handler_semantic`'s
//! namespace via a glob `use`, so both the parent module's own
//! "Composed patterns" and the `ext` submodule's Commit L matchers
//! see these names as if they were still local.
//!
//! x86 / x86-64 encoding notes used below:
//!
//! - A REX prefix is any byte in 0x40..=0x4F. We tolerate its presence
//!   in front of any pattern; the specific REX bits (W/R/X/B) don't
//!   change the *shape* we care about here (an indirect load is still
//!   an indirect load whether the register is RAX or R14).
//! - ModR/M layout: `mod(2) | reg(3) | rm(3)`. `mod=11` means reg-reg,
//!   `mod=00` means [reg] with no displacement (with r/m=4 needing a
//!   SIB byte and r/m=5 meaning RIP-relative on x64 / disp32 on x86 --
//!   both are treated as non-matches for "MOV r, [r]" here).

pub(super) fn contains_pair(bytecode: &[u8], a: u8, b: u8) -> bool {
    bytecode.windows(2).any(|w| w[0] == a && w[1] == b)
}

pub(super) fn skip_rex(bytecode: &[u8], pos: usize) -> usize {
    match bytecode.get(pos).copied() {
        Some(0x40..=0x4F) => pos + 1,
        _ => pos,
    }
}

/// True when `[reg]` mod-form is at (post-REX) `p` with the given opcode.
pub(super) fn is_indirect_at(bytecode: &[u8], p: usize, opcode: u8) -> bool {
    if bytecode.get(p).copied() != Some(opcode) {
        return false;
    }
    match bytecode.get(p + 1).copied() {
        Some(modrm) => {
            let mode = modrm & 0xC0;
            let rm = modrm & 0x07;
            mode == 0x00 && rm != 4 && rm != 5
        }
        None => false,
    }
}

/// True when `[reg+disp]` mod-form is at (post-REX) `p` with the given opcode.
pub(super) fn is_disp_at(bytecode: &[u8], p: usize, opcode: u8) -> bool {
    if bytecode.get(p).copied() != Some(opcode) {
        return false;
    }
    match bytecode.get(p + 1).copied() {
        Some(modrm) => {
            let mode = modrm & 0xC0;
            mode == 0x40 || mode == 0x80
        }
        None => false,
    }
}

/// Presence anywhere of `MOV r, [r]` (opcode 0x8B, mod=00).
pub(super) fn has_load_indirect(bytecode: &[u8]) -> bool {
    (0..bytecode.len()).any(|i| is_indirect_at(bytecode, skip_rex(bytecode, i), 0x8B))
}

/// Presence anywhere of `MOV [r], r` (opcode 0x89, mod=00).
pub(super) fn has_store_indirect(bytecode: &[u8]) -> bool {
    (0..bytecode.len()).any(|i| is_indirect_at(bytecode, skip_rex(bytecode, i), 0x89))
}

/// Presence anywhere of `MOV [r+disp], r` (opcode 0x89, mod=01 or mod=10).
pub(super) fn has_store_disp(bytecode: &[u8]) -> bool {
    (0..bytecode.len()).any(|i| is_disp_at(bytecode, skip_rex(bytecode, i), 0x89))
}

/// Presence anywhere of a group-1 imm8 op with the given `/n` reg-field.
/// `0x83 /0 imm8` = ADD reg, imm8 (reg encoded via 0xC0..=0xC7).
/// `0x83 /5 imm8` = SUB reg, imm8 (reg encoded via 0xE8..=0xEF).
pub(super) fn has_group1_imm8(bytecode: &[u8], modrm_lo: u8, modrm_hi: u8) -> bool {
    (0..bytecode.len()).any(|i| {
        let p = skip_rex(bytecode, i);
        bytecode.get(p).copied() == Some(0x83)
            && matches!(bytecode.get(p + 1).copied(), Some(b) if b >= modrm_lo && b <= modrm_hi)
    })
}

pub(super) fn has_add_reg_imm8(bytecode: &[u8]) -> bool {
    has_group1_imm8(bytecode, 0xC0, 0xC7)
}

pub(super) fn has_sub_reg_imm8(bytecode: &[u8]) -> bool {
    has_group1_imm8(bytecode, 0xE8, 0xEF)
}

/// Indirect JMP (`FF /4`) -- the shape VMP uses to tail-call the
/// dispatcher after every handler.
pub(super) fn has_indirect_jmp(bytecode: &[u8]) -> bool {
    (0..bytecode.len()).any(|i| {
        let p = skip_rex(bytecode, i);
        bytecode.get(p).copied() == Some(0xFF)
            && bytecode
                .get(p + 1)
                .copied()
                .map(|m| (m & 0x38) == 0x20)
                .unwrap_or(false)
    })
}

/// Count `NOT r/m` occurrences (opcode F7 /2, mod=11 encoded as 0xD0..=0xD7).
///
/// Uses a manual advance loop so a `REX F7 D?` triple isn't counted
/// twice (once with REX skipped, once with the loop landing on `F7`
/// directly). The `has_*` predicates above use `any()` and don't
/// need this because they only need one witness per bytecode -- the
/// double-scan is harmless for booleans but wrong for counts.
pub(super) fn count_not_ops(bytecode: &[u8]) -> usize {
    let mut count = 0usize;
    let mut i = 0usize;
    while i < bytecode.len() {
        let p = skip_rex(bytecode, i);
        if bytecode.get(p).copied() == Some(0xF7) && matches!(bytecode.get(p + 1).copied(), Some(0xD0..=0xD7)) {
            count += 1;
            i = p + 2;
        } else {
            i += 1;
        }
    }
    count
}

/// Presence of a reg-reg group op (mod=11) from the given opcode set.
/// Used for AND/OR/XOR in the De Morgan matchers.
pub(super) fn has_reg_reg_op(bytecode: &[u8], opcodes: &[u8]) -> bool {
    (0..bytecode.len()).any(|i| {
        let p = skip_rex(bytecode, i);
        match bytecode.get(p).copied() {
            Some(op) if opcodes.contains(&op) => bytecode
                .get(p + 1)
                .copied()
                .map(|m| (m & 0xC0) == 0xC0)
                .unwrap_or(false),
            _ => false,
        }
    })
}

pub(super) fn has_and_reg_reg(bytecode: &[u8]) -> bool {
    has_reg_reg_op(bytecode, &[0x21, 0x23])
}

pub(super) fn has_or_reg_reg(bytecode: &[u8]) -> bool {
    has_reg_reg_op(bytecode, &[0x09, 0x0B])
}

/// `ADD r,r`: opcodes 0x01 (r/m,r) and 0x03 (r,r/m), both mod=11.
/// Distinct from `has_add_reg_imm8` (the VSP `ADD reg,imm8` bump).
pub(super) fn has_add_reg_reg(bytecode: &[u8]) -> bool {
    has_reg_reg_op(bytecode, &[0x01, 0x03])
}

/// `MOV r, [r+disp]` (opcode 0x8B, mod=01/10) -- the CTX-slot load
/// shape that distinguishes `Pushreg` from `PushImm`.
pub(super) fn has_load_disp(bytecode: &[u8]) -> bool {
    (0..bytecode.len()).any(|i| is_disp_at(bytecode, skip_rex(bytecode, i), 0x8B))
}

pub(super) fn has_pushfq(bytecode: &[u8]) -> bool {
    bytecode.contains(&0x9C)
}

pub(super) fn has_popfq(bytecode: &[u8]) -> bool {
    bytecode.contains(&0x9D)
}

/// Count `MOV r, [r]` (opcode 0x8B, mod=00). Manual advance loop for
/// the same REX-double-count reason as `count_not_ops`.
pub(super) fn count_load_indirect(bytecode: &[u8]) -> usize {
    let mut count = 0usize;
    let mut i = 0usize;
    while i < bytecode.len() {
        let p = skip_rex(bytecode, i);
        if is_indirect_at(bytecode, p, 0x8B) {
            count += 1;
            i = p + 2;
        } else {
            i += 1;
        }
    }
    count
}

/// `XOR reg, imm` in any of the ordinary VMP-cryptor forms.
///
/// Covers, in order of frequency in real handlers per the public VMP
/// write-ups (back.engineering, r0da, vxcall):
/// - `0x83 /6` (mod=11): XOR reg, imm8 — the shortest form, 3 bytes.
/// - `0x81 /6` (mod=11): XOR reg, imm32 — 6 bytes, produced when the
///   key doesn't fit in imm8.
/// - `0x31 /r` (mod=11): XOR r/m32, reg32 — reg-reg form; VMP 2.x and
///   3.x both use `xor al, bl`-shape ops to fold the running key into
///   the decrypted byte (r0da §3, vxcall §rolling-key).
/// - `0x33 /r` (mod=11): XOR r32, r/m32 — reg-reg other operand order.
/// - `0x30 /r` / `0x32 /r` (mod=11): 8-bit reg-reg forms (`xor al, bl`
///   verbatim from r0da's disassembly).
///
/// The narrow imm8-only version of this primitive (Commit O) missed
/// the reg-reg forms that the synthetic `vjmp_key` handler and every
/// real VMP-3 handler actually emit, causing Ret to shadow Vjmp on
/// live samples. Broadened here in the T fix.
pub(super) fn has_xor_reg_imm(bytecode: &[u8]) -> bool {
    // 0x83 /6 imm8, mod=11 (ModR/M in 0xF0..=0xF7).
    if has_group1_imm8(bytecode, 0xF0, 0xF7) {
        return true;
    }
    // 0x81 /6 imm32, mod=11 (ModR/M in 0xF0..=0xF7). Same reg-encoding
    // as the imm8 form, differs only in the opcode byte and the fact
    // that we don't need to walk the 4-byte immediate to detect it.
    let imm32_hit = (0..bytecode.len()).any(|i| {
        let p = skip_rex(bytecode, i);
        bytecode.get(p).copied() == Some(0x81)
            && matches!(bytecode.get(p + 1).copied(), Some(b) if (0xF0..=0xF7).contains(&b))
    });
    if imm32_hit {
        return true;
    }
    // Reg-reg XOR — 0x30 (r/m8, r8), 0x31 (r/m32, r32), 0x32 (r8, r/m8),
    // 0x33 (r32, r/m32). All four require mod=11 to count as reg-reg.
    // `has_reg_reg_op` already enforces the mod=11 gate.
    has_reg_reg_op(bytecode, &[0x30, 0x31, 0x32, 0x33])
}

/// `ADD r, [r]` / `ADD r, [r+disp]` (opcode 0x03, `mod != 11`) -- the
/// handler-table base-plus-index add ordinary jump handlers use when
/// resolving a real dispatch-table entry. `Vemit`'s target comes
/// straight from the VIP stream with no such table lookup, so its
/// absence helps separate it from `Vjmp` (Commit O).
pub(super) fn has_add_reg_mem(bytecode: &[u8]) -> bool {
    (0..bytecode.len()).any(|i| {
        let p = skip_rex(bytecode, i);
        bytecode.get(p).copied() == Some(0x03)
            && bytecode
                .get(p + 1)
                .copied()
                .map(|m| (m & 0xC0) != 0xC0)
                .unwrap_or(false)
    })
}
