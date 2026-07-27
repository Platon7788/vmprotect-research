//! VMP-level semantic classifier for VM handlers.
//!
//! Runs after the byte-level x86 classification in
//! [`crate::handler_classifier`] and inspects the whole handler body (up
//! to ~100 bytes as read by `PEBinary::read_bytes_up_to`) for
//! multi-instruction fingerprints of well-known VMP handler shapes.
//!
//! Patterns are written from public descriptions of the VMP handler
//! pipeline (VSP fetch -> VSP adjust -> CTX store, etc.) and are
//! deliberately not copied from the GPL-licensed vmpattack / NoVmp
//! reference implementations mentioned in `AUDIT_REPORT.md`.
//!
//! Design notes:
//!
//! - `RET` and `VJMP` are the same shape at the byte level (both pop a
//!   value from the VM stack and jump to the dispatcher). We can't tell
//!   them apart without knowing whether the value came from a prior
//!   PUSH_IMM (VJMP) or a prior CALL-style handler (RET). This matcher
//!   labels the pattern `Vjmp` and does not attempt to produce `Ret`.
//! - `Push` (both the imm and reg flavours) is reported as
//!   [`VmpSemantic::Push`]; distinguishing imm-source from reg-source
//!   requires tracking which of VSP/VIP a load came from, which is
//!   beyond a stateless pattern matcher.

use crate::Bitness;

/// VMP-semantic handler category from the cross-validated taxonomy in
/// `AUDIT_REPORT.md` (Q2). Set on `HandlerClassification::vmp_semantic`
/// when a distinctive multi-instruction pattern is recognised.
///
/// `None` on the classification means "no VMP-level pattern matched";
/// the x86-instruction-level `handler_type` string remains the fallback
/// for consumers that don't yet consume this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[allow(missing_docs)]
pub enum VmpSemantic {
    // Data movement (VM-stack).
    Pop,
    Popstk,
    Push,
    Pushstk,
    Pushreg,
    Popreg,

    // Load/Store (VM-context / memory).
    Ldd,
    Str,

    // VSP manipulation.
    Vsetvsp,

    // Arithmetic base.
    Add,
    Div,
    Idiv,
    Mul,
    Imul,

    // Logic primitives (De Morgan).
    Nand,
    Nor,

    // Shifts / rotates.
    Shl,
    Shr,
    Shld,
    Shrd,
    Rcl,
    Rcr,

    // Flags.
    Popf,

    // System.
    Rdtsc,
    Cpuid,
    Lockor,
    VpushCr0,
    VpushCr3,

    // Control-flow.
    Vjmp,
    Ret,
    Vmexit,

    // Escape / meta.
    Vemit,
    Vexec,
    Vnop,
    Vunk,

    /// Recognised as a VMP handler shape but not matching any of the
    /// specific fingerprints implemented here.
    Unknown,
}

/// Stateless pattern-based semantic classifier.
pub struct SemanticMatcher;

impl SemanticMatcher {
    /// Classify a handler body. Returns `None` when no fingerprint
    /// matches (which the caller may prefer over `Some(Unknown)`
    /// depending on how it wants to fall through to the x86-level
    /// classification).
    ///
    /// Ordering is significant: more-distinctive fingerprints run first
    /// so weaker generic-shape matchers (Push/Pop) don't mask them.
    pub fn classify(bytecode: &[u8], bitness: Bitness) -> Option<VmpSemantic> {
        if bytecode.is_empty() {
            return None;
        }

        // Single-instruction distinctive fingerprints -- cheapest to
        // check and most reliable when present.
        if contains_pair(bytecode, 0x0F, 0x31) {
            return Some(VmpSemantic::Rdtsc);
        }
        if contains_pair(bytecode, 0x0F, 0xA2) {
            return Some(VmpSemantic::Cpuid);
        }

        // VMEXIT restores real registers and RETs to real x86. Presence
        // of a real x86 RET (0xC3) is only load-bearing here; all
        // in-VM control-flow handlers instead tail-JMP the dispatcher.
        if is_vmexit(bytecode) {
            return Some(VmpSemantic::Vmexit);
        }

        // De Morgan pairs: at least two NOTs plus the core logic op.
        if is_nand_shape(bytecode) {
            return Some(VmpSemantic::Nand);
        }
        if is_nor_shape(bytecode) {
            return Some(VmpSemantic::Nor);
        }

        // Push handlers reserve stack (SUB VSP, imm) then store to
        // [VSP] via a mod=00 MOV. Checked before Pop because SUB with
        // a small imm in this shape is very rare outside Push.
        if is_push_shape(bytecode) {
            return Some(VmpSemantic::Push);
        }

        // Pop handlers release stack (ADD VSP, imm) and store the
        // fetched value into the VM context at [CTX+disp] (mod=01/10).
        if is_pop_shape(bytecode) {
            return Some(VmpSemantic::Pop);
        }

        // VJMP: load from VM stack, adjust VSP, indirect-JMP -- no
        // context store. Placed after Pop so a Pop with a trailing
        // dispatcher JMP doesn't get relabelled.
        let _ = bitness;
        if is_vjmp_shape(bytecode) {
            return Some(VmpSemantic::Vjmp);
        }

        None
    }
}

// ---------------------------------------------------------------------
// Byte-level primitives.
//
// x86 / x86-64 encoding notes used below:
//
// - A REX prefix is any byte in 0x40..=0x4F. We tolerate its presence
//   in front of any pattern; the specific REX bits (W/R/X/B) don't
//   change the *shape* we care about here (an indirect load is still
//   an indirect load whether the register is RAX or R14).
// - ModR/M layout: `mod(2) | reg(3) | rm(3)`. `mod=11` means reg-reg,
//   `mod=00` means [reg] with no displacement (with r/m=4 needing a
//   SIB byte and r/m=5 meaning RIP-relative on x64 / disp32 on x86 --
//   both are treated as non-matches for "MOV r, [r]" here).
// ---------------------------------------------------------------------

fn contains_pair(bytecode: &[u8], a: u8, b: u8) -> bool {
    bytecode.windows(2).any(|w| w[0] == a && w[1] == b)
}

fn skip_rex(bytecode: &[u8], pos: usize) -> usize {
    match bytecode.get(pos).copied() {
        Some(0x40..=0x4F) => pos + 1,
        _ => pos,
    }
}

/// True when `[reg]` mod-form is at (post-REX) `p` with the given opcode.
fn is_indirect_at(bytecode: &[u8], p: usize, opcode: u8) -> bool {
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
fn is_disp_at(bytecode: &[u8], p: usize, opcode: u8) -> bool {
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
fn has_load_indirect(bytecode: &[u8]) -> bool {
    (0..bytecode.len()).any(|i| is_indirect_at(bytecode, skip_rex(bytecode, i), 0x8B))
}

/// Presence anywhere of `MOV [r], r` (opcode 0x89, mod=00).
fn has_store_indirect(bytecode: &[u8]) -> bool {
    (0..bytecode.len()).any(|i| is_indirect_at(bytecode, skip_rex(bytecode, i), 0x89))
}

/// Presence anywhere of `MOV [r+disp], r` (opcode 0x89, mod=01 or mod=10).
fn has_store_disp(bytecode: &[u8]) -> bool {
    (0..bytecode.len()).any(|i| is_disp_at(bytecode, skip_rex(bytecode, i), 0x89))
}

/// Presence anywhere of a group-1 imm8 op with the given `/n` reg-field.
/// `0x83 /0 imm8` = ADD reg, imm8 (reg encoded via 0xC0..=0xC7).
/// `0x83 /5 imm8` = SUB reg, imm8 (reg encoded via 0xE8..=0xEF).
fn has_group1_imm8(bytecode: &[u8], modrm_lo: u8, modrm_hi: u8) -> bool {
    (0..bytecode.len()).any(|i| {
        let p = skip_rex(bytecode, i);
        bytecode.get(p).copied() == Some(0x83)
            && matches!(bytecode.get(p + 1).copied(), Some(b) if b >= modrm_lo && b <= modrm_hi)
    })
}

fn has_add_reg_imm8(bytecode: &[u8]) -> bool {
    has_group1_imm8(bytecode, 0xC0, 0xC7)
}

fn has_sub_reg_imm8(bytecode: &[u8]) -> bool {
    has_group1_imm8(bytecode, 0xE8, 0xEF)
}

/// Indirect JMP (`FF /4`) -- the shape VMP uses to tail-call the
/// dispatcher after every handler.
fn has_indirect_jmp(bytecode: &[u8]) -> bool {
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
fn count_not_ops(bytecode: &[u8]) -> usize {
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
fn has_reg_reg_op(bytecode: &[u8], opcodes: &[u8]) -> bool {
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

fn has_and_reg_reg(bytecode: &[u8]) -> bool {
    has_reg_reg_op(bytecode, &[0x21, 0x23])
}

fn has_or_reg_reg(bytecode: &[u8]) -> bool {
    has_reg_reg_op(bytecode, &[0x09, 0x0B])
}

// ---------------------------------------------------------------------
// Composed patterns.
// ---------------------------------------------------------------------

/// VMEXIT: POPFQ (x64) or POPAD (x86) within a small window before a
/// real x86 RET (0xC3). The window avoids matching an unrelated 0x9D
/// byte appearing as an immediate value earlier in the handler.
fn is_vmexit(bytecode: &[u8]) -> bool {
    for (i, &b) in bytecode.iter().enumerate() {
        if b == 0x9D || b == 0x61 {
            let end = (i + 32).min(bytecode.len());
            if bytecode.get(i + 1..end).map(|s| s.contains(&0xC3)).unwrap_or(false) {
                return true;
            }
        }
    }
    false
}

fn is_nand_shape(bytecode: &[u8]) -> bool {
    count_not_ops(bytecode) >= 2 && has_and_reg_reg(bytecode)
}

fn is_nor_shape(bytecode: &[u8]) -> bool {
    count_not_ops(bytecode) >= 2 && has_or_reg_reg(bytecode)
}

fn is_push_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode) && has_sub_reg_imm8(bytecode) && has_store_indirect(bytecode)
}

fn is_pop_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode) && has_add_reg_imm8(bytecode) && has_store_disp(bytecode)
}

fn is_vjmp_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode)
        && has_add_reg_imm8(bytecode)
        && has_indirect_jmp(bytecode)
        && !has_store_disp(bytecode)
        && !has_store_indirect(bytecode)
}

#[cfg(test)]
#[path = "handler_semantic_tests.rs"]
mod tests;
