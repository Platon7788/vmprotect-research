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
//! P0-blocked pairs a stateless matcher CAN'T fully distinguish
//! (see `AUDIT_REPORT.md` Q2 + `RESEARCH_GAPS.md` §3.1):
//!
//! - `Ret` vs `Vjmp`: byte-identical; the label depends on whether
//!   the popped value came from a prior `PUSH_IMM` (Vjmp) or a
//!   `CALL`-style handler (Ret) -- cross-handler VM state we don't
//!   see. classify() emits `Vjmp`; the `Ret` enum variant is left
//!   in place so a later data-flow pass can promote it.
//! - `Popreg` vs `Pop`: also byte-identical. We only promote to
//!   `Popreg` on the tight `MOV [CTX+disp8], reg`-with-`disp8` in
//!   `[0, 0x80)` shape (small CTX-slot index for a GPR); all other
//!   Pop-shaped bodies fall through to `Pop`.
//! - `Ldd` vs `Str`: byte-identical without tracking whether the
//!   final indirect store lands on `[VSP]` (Ldd) or `[addr]` (Str);
//!   ordered Ldd-first with Str as a future-extension slot.
//!
//! classify() ordering runs most-distinctive fingerprints first
//! (single-instruction opcodes, then multi-op logic pairs, then
//! Add before the Push family) and puts the two catch-all shapes
//! (`Popf`, `Vsetvsp`) last so a stronger fingerprint always wins.
//!
//! Commit L extends this ordering (see `handler_semantic_ext.rs` for
//! the added matcher bodies):
//!
//! - `VpushCr0` / `VpushCr3` (distinctive 3-byte `0F 20` opcode) slot
//!   in right after `Cpuid`, alongside the other single-fingerprint
//!   system opcodes.
//! - `Lockor` (LOCK-prefixed OR) runs right after `Vmexit`.
//! - `Mul` / `Imul` / `Div` / `Idiv` (`0xF7 /n`) run after `Nand`/`Nor`
//!   but before `Add` -- they're a disjoint `/n` range from `Nand`/
//!   `Nor`'s `NOT` (`/2`) but conceptually belong to the arithmetic
//!   family `Add` heads.
//! - `Shl` / `Shr` / `Shld` / `Shrd` / `Rcl` / `Rcr` run right after
//!   `Add` -- same flag-touching arithmetic tier, PUSHFQ-gated.
//! - `Vnop` runs right before `Vsetvsp`: it is the strictly-narrower
//!   sibling (no load at all, vs. `Vsetvsp`'s single load-indirect),
//!   so it must be tried first or `Vsetvsp` would never lose to it.
//!
//! `Vemit` / `Vexec` are intentionally NOT implemented -- see
//! `handler_semantic_ext.rs` module doc for why the stateless-matcher
//! signal is too weak to distinguish them from `Vjmp` / a nested-VM
//! `Ldd`. `Popfd` (x86) vs `Popfq` (x64) are folded into the single
//! `Popf` variant -- both are byte-identical (`0x9D`); the bitness
//! parameter already threads through `classify()` if a future commit
//! wants to split them.

use crate::Bitness;

#[path = "handler_semantic_primitives.rs"]
mod primitives;
use primitives::*;

#[path = "handler_semantic_ext.rs"]
mod ext;
use ext::{
    is_div_shape, is_idiv_shape, is_imul_shape, is_lockor_shape, is_mul_shape, is_rcl_shape, is_rcr_shape,
    is_shl_shape, is_shld_shape, is_shr_shape, is_shrd_shape, is_vnop_shape, is_vpush_cr0_shape, is_vpush_cr3_shape,
};

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
    /// Push of an immediate operand read from the VIP stream. Split
    /// from the generic `Push` shape so downstream lifting can tell
    /// "constant literal in bytecode" apart from "value from a CTX
    /// register slot" (`Pushreg`). See module doc for the ordering.
    PushImm,
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
    /// Classify a handler body. `None` = no fingerprint matched.
    ///
    /// Ordering (see module doc for full rationale, Commit L extends
    /// it): single-instruction opcodes (Rdtsc, Cpuid, VpushCr0/Cr3)
    /// -> Vmexit -> Lockor -> Nand/Nor -> arithmetic-base F7 family
    /// (Mul/Imul/Div/Idiv) -> Add (before Push family, which shares
    /// load-indirect + store-indirect) -> shifts/rotates
    /// (Shl/Shr/Shld/Shrd/Rcl/Rcr) -> Ldd/Str (two-load shapes) ->
    /// Pushreg/PushImm/Push fallback -> Popreg/Pop fallback -> Vjmp
    /// -> Popf -> Vnop -> Vsetvsp catch-all.
    pub fn classify(bytecode: &[u8], bitness: Bitness) -> Option<VmpSemantic> {
        let _ = bitness;
        if bytecode.is_empty() {
            return None;
        }
        if contains_pair(bytecode, 0x0F, 0x31) {
            return Some(VmpSemantic::Rdtsc);
        }
        if contains_pair(bytecode, 0x0F, 0xA2) {
            return Some(VmpSemantic::Cpuid);
        }
        if is_vpush_cr0_shape(bytecode) {
            return Some(VmpSemantic::VpushCr0);
        }
        if is_vpush_cr3_shape(bytecode) {
            return Some(VmpSemantic::VpushCr3);
        }
        if is_vmexit(bytecode) {
            return Some(VmpSemantic::Vmexit);
        }
        if is_lockor_shape(bytecode) {
            return Some(VmpSemantic::Lockor);
        }
        if is_nand_shape(bytecode) {
            return Some(VmpSemantic::Nand);
        }
        if is_nor_shape(bytecode) {
            return Some(VmpSemantic::Nor);
        }
        if is_mul_shape(bytecode) {
            return Some(VmpSemantic::Mul);
        }
        if is_imul_shape(bytecode) {
            return Some(VmpSemantic::Imul);
        }
        if is_div_shape(bytecode) {
            return Some(VmpSemantic::Div);
        }
        if is_idiv_shape(bytecode) {
            return Some(VmpSemantic::Idiv);
        }
        if is_add_shape(bytecode) {
            return Some(VmpSemantic::Add);
        }
        if is_shl_shape(bytecode) {
            return Some(VmpSemantic::Shl);
        }
        if is_shr_shape(bytecode) {
            return Some(VmpSemantic::Shr);
        }
        if is_shld_shape(bytecode) {
            return Some(VmpSemantic::Shld);
        }
        if is_shrd_shape(bytecode) {
            return Some(VmpSemantic::Shrd);
        }
        if is_rcl_shape(bytecode) {
            return Some(VmpSemantic::Rcl);
        }
        if is_rcr_shape(bytecode) {
            return Some(VmpSemantic::Rcr);
        }
        if is_ldd_shape(bytecode) {
            return Some(VmpSemantic::Ldd);
        }
        if is_str_shape(bytecode) {
            return Some(VmpSemantic::Str);
        }
        if is_pushreg_shape(bytecode) {
            return Some(VmpSemantic::Pushreg);
        }
        if is_pushimm_shape(bytecode) {
            return Some(VmpSemantic::PushImm);
        }
        if is_push_shape(bytecode) {
            return Some(VmpSemantic::Push);
        }
        if is_popreg_shape(bytecode) {
            return Some(VmpSemantic::Popreg);
        }
        if is_pop_shape(bytecode) {
            return Some(VmpSemantic::Pop);
        }
        if is_vjmp_shape(bytecode) {
            return Some(VmpSemantic::Vjmp);
        }
        if is_popf_shape(bytecode) {
            return Some(VmpSemantic::Popf);
        }
        if is_vnop_shape(bytecode) {
            return Some(VmpSemantic::Vnop);
        }
        if is_vsetvsp_shape(bytecode) {
            return Some(VmpSemantic::Vsetvsp);
        }
        None
    }
}

// ---------------------------------------------------------------------
// Composed patterns.
//
// Byte-level primitives (contains_pair, skip_rex, has_load_indirect,
// etc.) live in `handler_semantic_primitives.rs`, glob-imported above.
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

/// Add: load-indirect + `add r,r` + PUSHFQ + store-indirect. Runs
/// before the Push family (strict superset of load+store shape).
fn is_add_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode) && has_add_reg_reg(bytecode) && has_pushfq(bytecode) && has_store_indirect(bytecode)
}

/// Ldd: two indirect loads, indirect store, imm8 VSP tweak.
/// Byte-identical to `Str`; classify() runs Ldd first.
fn is_ldd_shape(bytecode: &[u8]) -> bool {
    count_load_indirect(bytecode) >= 2 && has_store_indirect(bytecode) && has_add_reg_imm8(bytecode)
}

/// Str: Ldd's shape plus `!has_store_disp`. Retained as a future
/// register-tracking hook -- Ldd wins in classify() today.
fn is_str_shape(bytecode: &[u8]) -> bool {
    count_load_indirect(bytecode) >= 2
        && has_store_indirect(bytecode)
        && has_add_reg_imm8(bytecode)
        && !has_store_disp(bytecode)
}

/// PushReg: load-disp (CTX slot) + SUB VSP + store-indirect.
fn is_pushreg_shape(bytecode: &[u8]) -> bool {
    has_load_disp(bytecode) && has_sub_reg_imm8(bytecode) && has_store_indirect(bytecode)
}

/// PushImm: load-indirect (VIP stream) + SUB VSP + store-indirect,
/// with `!has_load_disp` so a CTX-load body picks `Pushreg` instead.
fn is_pushimm_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode)
        && has_sub_reg_imm8(bytecode)
        && has_store_indirect(bytecode)
        && !has_load_disp(bytecode)
}

/// Popreg: Pop-shape with exactly one `MOV [r+disp8], r` where
/// `disp8 < 0x80` (small CTX-slot index for a GPR). Else falls
/// through to `Pop`.
fn is_popreg_shape(bytecode: &[u8]) -> bool {
    if !is_pop_shape(bytecode) {
        return false;
    }
    let mut store_count = 0usize;
    let mut first_disp8: Option<u8> = None;
    let mut i = 0usize;
    while i < bytecode.len() {
        let p = skip_rex(bytecode, i);
        if bytecode.get(p).copied() == Some(0x89) {
            if let Some(modrm) = bytecode.get(p + 1).copied() {
                let mode = modrm & 0xC0;
                if mode == 0x40 || mode == 0x80 {
                    let rm = modrm & 0x07;
                    let disp_start = if rm == 4 { p + 3 } else { p + 2 };
                    if store_count == 0 && mode == 0x40 {
                        first_disp8 = bytecode.get(disp_start).copied();
                    }
                    store_count += 1;
                    i = if mode == 0x40 { disp_start + 1 } else { disp_start + 4 };
                    continue;
                }
            }
        }
        i += 1;
    }
    store_count == 1 && matches!(first_disp8, Some(d) if d < 0x80)
}

/// Vsetvsp: load-indirect only, no adjust, no stores, no jump.
/// Strictest "matched nothing else" catch-all; runs last.
fn is_vsetvsp_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode)
        && !has_add_reg_imm8(bytecode)
        && !has_sub_reg_imm8(bytecode)
        && !has_store_indirect(bytecode)
        && !has_store_disp(bytecode)
        && !has_indirect_jmp(bytecode)
}

/// Popf: bare POPFQ (0x9D). Vmexit runs first; anything reaching
/// here with 0x9D is a real POPF outside a vmexit frame.
fn is_popf_shape(bytecode: &[u8]) -> bool {
    has_popfq(bytecode)
}

#[cfg(test)]
#[path = "handler_semantic_tests.rs"]
mod tests;
