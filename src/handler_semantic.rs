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
//! - `Ret` vs `Vjmp`: byte-identical in general; Commit O narrows this
//!   with a body-length + no-operand-decrypt heuristic (public
//!   writeups describe `Ret` as the shortest handler in the table --
//!   see `handler_semantic_ext.rs` Group D) instead of leaving it
//!   permanently unpromoted. Longer bodies with the same shape still
//!   fall through to `Vjmp`.
//! - `Popreg` vs `Pop`: also byte-identical. We only promote to
//!   `Popreg` on the tight `MOV [CTX+disp8], reg`-with-`disp8` in
//!   `[0, 0x80)` shape (small CTX-slot index for a GPR); all other
//!   Pop-shaped bodies fall through to `Pop`.
//! - `Ldd` vs `Str`: byte-identical without tracking whether the
//!   final indirect store lands on `[VSP]` (Ldd) or `[addr]` (Str);
//!   ordered Ldd-first with Str as a future-extension slot.
//! - `PushImm` vs `Pushstk` (Commit O): also byte-identical in the
//!   common case -- `PushImm`'s shape never inspects `has_store_disp`,
//!   so whenever `Pushstk`'s stricter shape (same four conditions plus
//!   `!has_store_disp`) holds, `PushImm`'s weaker shape holds too and
//!   wins by running first. Same "future-extension slot, verified via
//!   its own matcher fn rather than through `classify()`" treatment as
//!   `Str`; see `handler_semantic_ext_tests.rs` for a direct-matcher
//!   test. `Popstk` has no such collision with `Popreg` (`Popreg`
//!   *requires* `has_store_disp`, so the two are disjoint) and IS
//!   reachable through `classify()`.
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
//! `Popfd` (x86) vs `Popfq` (x64) are folded into the single `Popf`
//! variant -- both are byte-identical (`0x9D`); the bitness parameter
//! already threads through `classify()` if a future commit wants to
//! split them.
//!
//! Commit O closes out the remaining taxonomy entries (see
//! `handler_semantic_ext.rs` Groups D/E/F for the added matcher
//! bodies):
//!
//! - `Ret` runs right BEFORE `Vjmp`: same load+adjust+indirect-jump
//!   shape, gated to short (`< 30` byte), non-decrypting bodies. A
//!   longer body with the identical shape still falls through to
//!   `Vjmp`, which is the far more common label.
//! - `Vemit` runs right AFTER `Vjmp` -- it is the rarer "raw VIP
//!   literal, no table lookup, no decrypt" escape shape, and `Vexec`
//!   (nested VM entry) is folded into it as statelessly identical
//!   (see `handler_semantic_ext.rs` Group E).
//! - `Popstk` / `Pushstk` run right BEFORE their generic `Pop` / `Push`
//!   fallbacks: same load+adjust+store skeleton, narrowed to bodies
//!   that touch no CTX slot in either direction (strict subsets).
//!   `Pushstk` additionally sits AFTER `PushImm` -- see the `PushImm`
//!   vs `Pushstk` P0-blocked note above for why.
//! - `Popf`'s shape is refined in place (same ordering slot) to also
//!   require a short body with the `0x9D` byte near the tail, cutting
//!   false positives from a `0x9D` deep inside an otherwise unrelated
//!   longer body.
//! - `Vsetvsp`'s catch-all shape is refined in place (same ordering
//!   slot, still last) to also require a short body with exactly one
//!   load -- `Vnop` remains strictly narrower and must still run first.

use crate::Bitness;

#[path = "handler_semantic_primitives.rs"]
mod primitives;
use primitives::*;

#[path = "handler_semantic_ext.rs"]
mod ext;
use ext::{
    is_div_shape, is_idiv_shape, is_imul_shape, is_lockor_shape, is_mul_shape, is_popstk_shape, is_pushstk_shape,
    is_rcl_shape, is_rcr_shape, is_ret_shape, is_shl_shape, is_shld_shape, is_shr_shape, is_shrd_shape, is_vemit_shape,
    is_vnop_shape, is_vpush_cr0_shape, is_vpush_cr3_shape,
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
    /// VM-stack-to-VM-stack pop: same load+adjust+store shape as `Pop`
    /// but never touches a CTX slot in either direction (Commit O).
    /// Runs before the generic `Pop` fallback -- strict subset.
    Popstk,
    Push,
    /// VM-stack-to-VM-stack push: `Popstk`'s counterpart. Same
    /// byte-identical-collision situation as `Ldd`/`Str` (see module
    /// doc): `PushImm`'s shape doesn't check `has_store_disp`, so it
    /// always wins first for a body that would also satisfy this
    /// shape. Kept as a future-extension slot, verified directly via
    /// its internal matcher fn rather than through `classify()`.
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
    /// Real x86 return via the VM: byte-identical to `Vjmp`'s
    /// load+adjust+indirect-jump shape, distinguished by a short body
    /// and the absence of any operand-decrypt XOR (Commit O). Runs
    /// before `Vjmp` in `classify()`; a longer body with the same
    /// shape still falls through to `Vjmp`.
    Ret,
    Vmexit,

    // Escape / meta.
    /// Raw x86 emit / escape: indirect jump to a VIP-stream-derived
    /// address with no handler-table lookup (no XOR-decrypt, no
    /// ADD-from-memory) -- Commit O. Runs after `Vjmp` (the far more
    /// common shape gets first claim).
    Vemit,
    /// Nested VM entry: statelessly identical to `Vemit` from a
    /// single-handler-body view (both are "jump to a VIP-derived
    /// address, no table lookup"); `classify()` only ever emits
    /// `Vemit` for this shape. Kept as a distinct enum variant for a
    /// future cross-handler pass that can tell "lands in real code"
    /// from "lands on another dispatcher prologue".
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
    /// Ordering (see module doc for full rationale; Commit L extends
    /// it, Commit O extends it further): single-instruction opcodes
    /// (Rdtsc, Cpuid, VpushCr0/Cr3) -> Vmexit -> Lockor -> Nand/Nor ->
    /// arithmetic-base F7 family (Mul/Imul/Div/Idiv) -> Add (before
    /// Push family, which shares load-indirect + store-indirect) ->
    /// shifts/rotates (Shl/Shr/Shld/Shrd/Rcl/Rcr) -> Ldd/Str (two-load
    /// shapes) -> Pushreg/PushImm/Pushstk/Push fallback ->
    /// Popreg/Popstk/Pop fallback -> Ret -> Vjmp -> Vemit -> Popf ->
    /// Vnop -> Vsetvsp catch-all. `Popstk` sits directly ahead of the
    /// generic `Pop` fallback (strict subset, and disjoint from
    /// `Popreg`, so it's actually reachable); `Pushstk` sits directly
    /// after `PushImm` (byte-identical collision -- `PushImm` always
    /// wins first, see module doc); `Ret` sits directly ahead of
    /// `Vjmp` (short-body variant of the same shape); `Vemit` sits
    /// directly after `Vjmp` (rarer sibling shape, folds in the
    /// statelessly-identical `Vexec`).
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
        if is_pushstk_shape(bytecode) {
            return Some(VmpSemantic::Pushstk);
        }
        if is_push_shape(bytecode) {
            return Some(VmpSemantic::Push);
        }
        if is_popreg_shape(bytecode) {
            return Some(VmpSemantic::Popreg);
        }
        if is_popstk_shape(bytecode) {
            return Some(VmpSemantic::Popstk);
        }
        if is_pop_shape(bytecode) {
            return Some(VmpSemantic::Pop);
        }
        if is_ret_shape(bytecode) {
            return Some(VmpSemantic::Ret);
        }
        if is_vjmp_shape(bytecode) {
            return Some(VmpSemantic::Vjmp);
        }
        if is_vemit_shape(bytecode) {
            return Some(VmpSemantic::Vemit);
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

/// Vsetvsp: exactly one load-indirect, no adjust, no stores, no jump,
/// AND a short body (< 12 bytes). Strictest "matched nothing else"
/// catch-all; runs last. Commit O adds the length + single-load gate
/// -- the shape is intrinsically similar to `Vnop`'s (both are "just a
/// VSP touch and nothing else"), so `Vnop` must keep running first or
/// `Vsetvsp` would never lose to it; the extra gate here only trims
/// false positives from a longer body that happens to carry a lone
/// stray load-indirect nowhere near the real handler-body pattern.
fn is_vsetvsp_shape(bytecode: &[u8]) -> bool {
    bytecode.len() < 12
        && count_load_indirect(bytecode) == 1
        && !has_add_reg_imm8(bytecode)
        && !has_sub_reg_imm8(bytecode)
        && !has_store_indirect(bytecode)
        && !has_store_disp(bytecode)
        && !has_indirect_jmp(bytecode)
}

/// Popf: bare POPFQ (0x9D), refined (Commit O) to require a short body
/// (< 20 bytes) with the 0x9D sitting within the last 8 bytes. Vmexit
/// runs first, so this only sees POPF outside a vmexit frame; the
/// added position/length gate keeps a 0x9D deep inside a longer,
/// unrelated body (e.g. a coincidental immediate byte) from being
/// misread as a real POPF handler.
fn is_popf_shape(bytecode: &[u8]) -> bool {
    if bytecode.len() >= 20 {
        return false;
    }
    let near_end = bytecode.len().saturating_sub(8);
    has_popfq(&bytecode[near_end..])
}

#[cfg(test)]
#[path = "handler_semantic_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "handler_semantic_o_tests.rs"]
mod tests_o;
