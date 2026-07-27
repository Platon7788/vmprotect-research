//! Unit tests for Commit O's remaining matchers (`Ret`, `Vemit`,
//! `Popstk`, `Pushstk`).
//!
//! Split out of `handler_semantic_tests.rs` via `#[cfg(test)] #[path =
//! ...] mod tests_o;` in `handler_semantic.rs` so neither test file
//! crosses the project's 500-line ceiling (see `CLAUDE.md`), same
//! convention as `handler_semantic_ext_tests.rs` for Commit L. Group
//! ordering tests (`Popf` short-body refinement, `Vjmp`-vs-`Ret`
//! length gate) that touch pre-existing matchers stay in
//! `handler_semantic_tests.rs`; this file covers only the four
//! brand-new matcher shapes.

use super::*;

#[test]
fn ret_shape_detected_x64() {
    // MOV rax, [r14]; ADD r14, 8; JMP [rip+disp32] -- byte-identical
    // to the Vjmp shape, but short (< 30 bytes) with no XOR-decrypt of
    // the loaded operand: Commit O's Ret heuristic (public writeups
    // describe Ret as the shortest handler in the dispatch table --
    // pop a VM-stack return address and go).
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]
        0x49, 0x83, 0xC6, 0x08, // ADD r14, 8
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // JMP [rip+disp32]
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Ret));
}

#[test]
fn ret_shape_rejected_when_xor_decrypt_present_falls_to_vjmp() {
    // Same short Vjmp-shape body, but with an XOR reg,imm8 decrypt
    // step inserted (0x83 /6 -> modrm in 0xF0..=0xF7): Ret's
    // `!has_xor_reg_imm` gate rejects it, so classify() falls through
    // to the ordinary Vjmp label even though the body is short.
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]
        0x83, 0xF0, 0x05, // XOR eax, 5           <- operand decrypt
        0x49, 0x83, 0xC6, 0x08, // ADD r14, 8
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Vjmp));
}

#[test]
fn vemit_shape_detected_x64() {
    // MOV rax, [r14]; JMP [rip+disp32] -- indirect jump straight off a
    // VIP-stream load with no VSP adjust (so it isn't Vjmp/Ret), no
    // XOR-decrypt, and no table-lookup ADD-from-memory: Commit O's
    // Vemit raw-emit escape shape. `Vexec` (nested-VM entry) is
    // statelessly identical and folds into this same label.
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // JMP [rip+disp32]
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Vemit));
}

#[test]
fn vemit_rejected_when_xor_decrypt_present() {
    // Same shape as `vemit_shape_detected_x64` but with an XOR
    // reg,imm8 decrypt inserted: Vemit's `!has_xor_reg_imm` gate
    // rejects it, and no other matcher fits this residual shape
    // (Vsetvsp is documented unreachable on any body carrying a
    // dispatcher tail JMP, see the `is_vsetvsp_shape` doc comment).
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]
        0x83, 0xF0, 0x05, // XOR eax, 5
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), None);
}

#[test]
fn popstk_shape_detected_x64() {
    // MOV rax, [r14]; ADD r14, 8; MOV [r14], rax; JMP [rip+disp32] --
    // same load+adjust+store skeleton as Pop, but the result lands
    // back on the VM stack (store-indirect) instead of a CTX slot
    // (store-disp), and no CTX slot is touched in either direction:
    // Commit O's Popstk (VM-stack-to-VM-stack transfer).
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]
        0x49, 0x83, 0xC6, 0x08, // ADD r14, 8
        0x49, 0x89, 0x06, // MOV [r14], rax
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::Popstk)
    );
}

#[test]
fn popstk_loses_to_popreg_when_ctx_store_present() {
    // Same Popstk skeleton, but with an added CTX-slot store: the
    // `!has_store_disp` gate in `is_popstk_shape` rejects it, and the
    // stronger Popreg fingerprint (single disp8 CTX store) claims the
    // body first anyway.
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]
        0x49, 0x83, 0xC6, 0x08, // ADD r14, 8
        0x49, 0x89, 0x06, // MOV [r14], rax        store-indirect
        0x48, 0x89, 0x45, 0x08, // MOV [rbp+8], rax  store-disp (CTX)
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::Popreg)
    );
}

#[test]
fn pushstk_matcher_matches_pushimm_shape_directly() {
    // PushImm wins in classify() (see `handler_semantic.rs` module
    // doc, "PushImm vs Pushstk"), so Pushstk is verified via its
    // internal matcher -- same "future-extension slot" treatment as
    // `Str` vs `Ldd`. This is the exact body from
    // `pushimm_shape_detected_x64` in `handler_semantic_tests.rs`.
    let body = [
        0x49, 0x8B, 0x07, // MOV rax, [r15]
        0x49, 0x83, 0xEE, 0x08, // SUB r14, 8
        0x49, 0x89, 0x06, // MOV [r14], rax
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert!(is_pushstk_shape(&body));
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::PushImm)
    );
    // A CTX-slot store disqualifies Pushstk but not PushImm.
    let body_with_ctx_store = [
        0x49, 0x8B, 0x07, 0x49, 0x83, 0xEE, 0x08, 0x49, 0x89, 0x06, 0x48, 0x89, 0x45, 0x08, 0xFF, 0x25, 0x00, 0x00,
        0x00, 0x00,
    ];
    assert!(!is_pushstk_shape(&body_with_ctx_store));
}

#[test]
fn short_popfq_near_tail_without_ret_is_popf() {
    // "POPFQ but no real RET nearby", refined (Commit O) to a short
    // body (< 20 bytes) with the 0x9D inside the last 8 bytes -- the
    // shape Popf actually targets after the refinement (see the
    // rejected-deep-0x9D counterpart in `handler_semantic_tests.rs`).
    let body = [0x90, 0x90, 0x90, 0x9D, 0x90];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Popf));
}

// -----------------------------------------------------------------
// Commit T regressions
// -----------------------------------------------------------------

/// Commit T: `has_xor_reg_imm` broadening from imm8-only to imm32 +
/// reg-reg. A Vjmp-shape body containing `xor rbx, imm32` (0x81 /6)
/// now correctly disqualifies from Ret and falls through to Vjmp.
///
/// Pre-T, only 0x83 /6 (imm8) was recognised. VMP 3.x's rolling-key
/// stream cipher emits `xor rXX, imm32` whenever the key exceeds
/// imm8 range, which is often — so pre-T handlers with a legitimate
/// crypto XOR were misclassified as Ret.
#[test]
fn t_xor_imm32_form_disqualifies_ret_and_lands_on_vjmp() {
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]
        0x49, 0x83, 0xC6, 0x08, // ADD r14, 8
        0x48, 0x81, 0xF3, 0xDE, 0xAD, 0xBE, 0xEF, // XOR rbx, 0xEFBEADDE (imm32)
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // JMP [rip+0]
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Vjmp));
}

/// Commit T: `has_xor_reg_imm` broadening for the reg-reg XOR form.
/// r0da / vxcall document `xor al, bl`-shape ops as the running-key
/// folding step VMP 2.x/3.x actually emits in most handlers. A
/// Vjmp-shape body containing `xor al, bl` (0x30 /r, mod=11) now
/// disqualifies from Ret.
#[test]
fn t_xor_reg_reg_form_disqualifies_ret_and_lands_on_vjmp() {
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]
        0x49, 0x83, 0xC6, 0x08, // ADD r14, 8
        0x30, 0xD8, // XOR al, bl (0x30 /r mod=11)
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Vjmp));
}

/// Commit T: `confidence_for(Ret)` correctly ranks above Vjmp now.
/// Pre-T inverted the "stricter matcher wins higher confidence"
/// contract: Ret was 50, Vjmp was 85, even though Ret is a strict
/// subset (body < 30 AND no XOR AND Vjmp-shape).
#[test]
fn t_ret_confidence_is_higher_than_vjmp() {
    assert!(confidence_for(VmpSemantic::Ret) > confidence_for(VmpSemantic::Vjmp));
    assert!(confidence_for(VmpSemantic::Vemit) > confidence_for(VmpSemantic::Vjmp));
}

/// Commit T: Vsetvsp is documented unreachable on any body carrying a
/// dispatcher tail JMP (see the shape's doc comment). Vemit's simpler
/// `load-indirect + indirect_jmp + !has_xor + !has_add_reg_mem` shape
/// always wins first. This test pins the current behaviour so the
/// audit note stays visible: a short "just a load + tail JMP" body
/// classifies as Vemit, not Vsetvsp.
#[test]
fn t_short_body_with_dispatcher_tail_is_vemit_not_vsetvsp() {
    let body = [
        0x48, 0x8B, 0x03, // MOV rax, [rbx]
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Vemit));
}
