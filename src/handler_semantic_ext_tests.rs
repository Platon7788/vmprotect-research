//! Unit tests for Commit L's extended matchers (`handler_semantic_ext.rs`).
//!
//! Split from `handler_semantic_ext.rs` via `#[cfg(test)] #[path = ...]
//! mod tests;` so the impl file stays under the project's 500-line
//! ceiling (see `CLAUDE.md`), same convention as `handler_semantic_tests.rs`.

use crate::handler_semantic::{SemanticMatcher, VmpSemantic};
use crate::Bitness;

// -----------------------------------------------------------------
// Group A: Mul / Imul / Div / Idiv (`0xF7 /n`).
// -----------------------------------------------------------------

#[test]
fn mul_shape_detected_x64() {
    // MOV rax, [r14]; MUL rax (F7 /4 -> modrm 0xE0); MOV [r14], rax; JMP [rip]
    let body = [
        0x49, 0x8B, 0x06, 0x48, 0xF7, 0xE0, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Mul));
}

#[test]
fn imul_shape_detected_x64() {
    // Same as mul_shape_detected_x64 but F7 /5 (modrm 0xE8) -> IMUL.
    let body = [
        0x49, 0x8B, 0x06, 0x48, 0xF7, 0xE8, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Imul));
}

#[test]
fn div_shape_detected_x64() {
    // F7 /6 (modrm 0xF0) -> DIV.
    let body = [
        0x49, 0x8B, 0x06, 0x48, 0xF7, 0xF0, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Div));
}

#[test]
fn idiv_shape_detected_x64() {
    // F7 /7 (modrm 0xF8) -> IDIV.
    let body = [
        0x49, 0x8B, 0x06, 0x48, 0xF7, 0xF8, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Idiv));
}

#[test]
fn mul_missing_store_falls_through_to_vsetvsp() {
    // Load + MUL op but no store and no dispatcher jump: is_mul_shape
    // needs the store, so this body drops to the Vsetvsp catch-all
    // (load-indirect only, no adjust/store/jump) instead of None.
    let body = [0x49, 0x8B, 0x06, 0x48, 0xF7, 0xE0];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::Vsetvsp)
    );
}

#[test]
fn mul_wins_over_add_when_both_shapes_present() {
    // Body carries both a Mul-shape (load-indirect + F7 /4 + store)
    // and an Add-shape (load-indirect + add r,r + PUSHFQ + store).
    // Mul is ranked ahead of Add in classify() (Commit L ordering).
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]      load-indirect
        0x48, 0xF7, 0xE0, // MUL rax             F7 /4
        0x48, 0x01, 0xC8, // ADD rax, rcx        add r,r
        0x9C, // PUSHFQ
        0x49, 0x89, 0x06, // MOV [r14], rax      store-indirect
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Mul));
}

// -----------------------------------------------------------------
// Group B: shifts / rotates.
// -----------------------------------------------------------------

#[test]
fn shl_shape_detected_x64() {
    // MOV rax, [r14]; SHL eax, cl (D3 /4 -> modrm 0xE0); PUSHFQ; MOV [r14], rax; JMP [rip]
    let body = [
        0x49, 0x8B, 0x06, 0xD3, 0xE0, 0x9C, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Shl));
}

#[test]
fn shr_shape_detected_x64() {
    // D3 /5 -> modrm 0xE8 -> SHR.
    let body = [
        0x49, 0x8B, 0x06, 0xD3, 0xE8, 0x9C, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Shr));
}

#[test]
fn shld_shape_detected_x64() {
    // MOV rax, [r14]; SHLD ecx, eax, 4 (0F A4 /r imm8); PUSHFQ; MOV [r14], rax; JMP [rip]
    let body = [
        0x49, 0x8B, 0x06, 0x0F, 0xA4, 0xC1, 0x04, 0x9C, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Shld));
}

#[test]
fn shrd_shape_detected_x64() {
    // SHRD ecx, eax, 4 (0F AC /r imm8).
    let body = [
        0x49, 0x8B, 0x06, 0x0F, 0xAC, 0xC1, 0x04, 0x9C, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Shrd));
}

#[test]
fn rcl_shape_detected_x64() {
    // D3 /2 -> modrm 0xD0 -> RCL.
    let body = [
        0x49, 0x8B, 0x06, 0xD3, 0xD0, 0x9C, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Rcl));
}

#[test]
fn rcr_shape_detected_x64() {
    // D3 /3 -> modrm 0xD8 -> RCR.
    let body = [
        0x49, 0x8B, 0x06, 0xD3, 0xD8, 0x9C, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Rcr));
}

#[test]
fn shl_missing_pushfq_falls_through_to_vemit() {
    // Same as shl_shape_detected_x64 but PUSHFQ removed: is_shl_shape
    // needs the flags store; Vsetvsp's `!has_store_indirect` guard
    // rejects the surviving shape and Vjmp needs an imm8 VSP adjust we
    // don't have. Commit O's Vemit (load-indirect + indirect-jmp, no
    // XOR-decrypt, no ADD-from-memory) now claims this residual shape
    // instead of leaving it as None.
    let body = [
        0x49, 0x8B, 0x06, 0xD3, 0xE0, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Vemit));
}

#[test]
fn shl_wins_over_shr_when_both_ops_present() {
    // Body carries both a SHL (D3 /4) and a SHR (D3 /5) op. Shl is
    // checked first in classify() (Commit L Group B order).
    let body = [
        0x49, 0x8B, 0x06, 0xD3, 0xE0, 0xD3, 0xE8, 0x9C, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Shl));
}

// -----------------------------------------------------------------
// Group C: system / escape.
// -----------------------------------------------------------------

#[test]
fn lockor_reg_reg_detected() {
    // LOCK OR eax, ecx: F0 09 C8.
    let body = [0xF0, 0x09, 0xC8];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::Lockor)
    );
}

#[test]
fn lockor_reg_imm8_detected() {
    // LOCK OR eax, 5: F0 83 /1 imm8 -> modrm 0xC8 (mod=11, reg=1, rm=0).
    let body = [0xF0, 0x83, 0xC8, 0x05];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::Lockor)
    );
}

#[test]
fn lockor_rejects_non_or_opcode_after_lock() {
    // LOCK ADD eax, ecx (opcode 0x01, not 0x09/0x0B/0x83 /1): Lockor's
    // opcode match fails; this fabricated 3-byte body has no other
    // load/store shape to fall through to, so classify() yields None.
    let body = [0xF0, 0x01, 0xC8];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), None);
}

#[test]
fn vpush_cr0_shape_detected() {
    // MOV eax, cr0: 0F 20 C0 (mod=11, reg=0, rm=0).
    let body = [0x0F, 0x20, 0xC0];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::VpushCr0)
    );
}

#[test]
fn vpush_cr3_shape_detected() {
    // MOV eax, cr3: 0F 20 D8 (mod=11, reg=3, rm=0).
    let body = [0x0F, 0x20, 0xD8];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::VpushCr3)
    );
}

#[test]
fn vpush_cr0_wins_over_cr3_when_both_present() {
    // Cr0 is checked first in classify() (right after Cpuid).
    let body = [0x0F, 0x20, 0xC0, 0x0F, 0x20, 0xD8];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::VpushCr0)
    );
}

#[test]
fn mov_cr_rejects_non_register_mod() {
    // 0F 20 00: mod=00, not the required mod=11 register-direct form
    // -- neither Cr0 nor Cr3 fires, and this 3-byte body fits no
    // other shape either.
    let body = [0x0F, 0x20, 0x00];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), None);
}

#[test]
fn vnop_shape_detected() {
    // Only the dispatcher tail JMP -- no load, no store, no VSP math.
    let body = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Vnop));
}

#[test]
fn vnop_rejected_when_vsp_adjust_present() {
    // ADD eax, 8 before the tail JMP: is_vnop_shape's `!has_add_reg_imm8`
    // guard rejects it. No load-indirect exists either, so Vsetvsp
    // (which requires one) can't claim it -- classify() yields None.
    let body = [0x83, 0xC0, 0x08, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), None);
}

#[test]
fn vnop_rejected_when_load_indirect_present() {
    // A real load-indirect present alongside the tail JMP: Vnop's
    // `!has_load_indirect` guard rejects it, and Vsetvsp's
    // `!has_indirect_jmp` guard rejects it too (jmp present) -- both
    // catch-alls lose. This exact load+jmp shape is also Commit O's
    // canonical Vemit fingerprint (no XOR-decrypt, no ADD-from-memory),
    // so it now claims the body instead of leaving it as None.
    let body = [0x49, 0x8B, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Vemit));
}
