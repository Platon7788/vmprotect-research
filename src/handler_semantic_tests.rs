//! Unit tests for `handler_semantic`.
//!
//! Split from `handler_semantic.rs` via `#[cfg(test)] #[path = ...] mod
//! tests;` so the impl file stays under the project's 500-line ceiling
//! (see `CLAUDE.md`). Compiled only under `#[cfg(test)]`.

use super::*;

// -----------------------------------------------------------------
// Positive tests -- one per implemented pattern.
// -----------------------------------------------------------------

#[test]
fn rdtsc_x64_detected() {
    // RDTSC + tail JMP [rip+0]
    let body = [0x0F, 0x31, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Rdtsc));
}

#[test]
fn rdtsc_x86_detected() {
    let body = [0x0F, 0x31, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X86), Some(VmpSemantic::Rdtsc));
}

#[test]
fn cpuid_detected() {
    let body = [0x0F, 0xA2, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Cpuid));
}

#[test]
fn vmexit_x64_popfq_ret_detected() {
    // POPFQ then a couple of POPs then RET.
    let body = [0x9D, 0x58, 0x59, 0x5A, 0xC3];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::Vmexit)
    );
}

#[test]
fn vmexit_x86_popad_ret_detected() {
    // POPAD (x86-only opcode 0x61) then RET.
    let body = [0x61, 0x9D, 0xC3];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X86),
        Some(VmpSemantic::Vmexit)
    );
}

#[test]
fn nand_shape_detected_x64() {
    // NOT rax; NOT rcx; AND rax, rcx; JMP [rip]
    let body = [
        0x48, 0xF7, 0xD0, // NOT rax
        0x48, 0xF7, 0xD1, // NOT rcx
        0x48, 0x21, 0xC8, // AND rax, rcx
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Nand));
}

#[test]
fn nor_shape_detected_x64() {
    // NOT rax; NOT rcx; OR rax, rcx; JMP [rip]
    let body = [
        0x48, 0xF7, 0xD0, // NOT rax
        0x48, 0xF7, 0xD1, // NOT rcx
        0x48, 0x09, 0xC8, // OR rax, rcx
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Nor));
}

#[test]
fn nor_shape_detected_x86_without_rex() {
    // On x86 the same shape exists without REX prefixes.
    let body = [
        0xF7, 0xD0, // NOT eax
        0xF7, 0xD1, // NOT ecx
        0x09, 0xC8, // OR eax, ecx
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X86), Some(VmpSemantic::Nor));
}

#[test]
fn pop_shape_detected_x64_promotes_to_popreg() {
    // MOV rax, [r14]; ADD r14, 8; MOV [rbp+8], rax; JMP [rip]
    // Commit G split: the single-disp8-in-[0, 0x80) CTX store makes
    // this a `Popreg` under the new ordering, not the coarser `Pop`.
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]
        0x49, 0x83, 0xC6, 0x08, // ADD r14, 8
        0x48, 0x89, 0x45, 0x08, // MOV [rbp+8], rax
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::Popreg)
    );
}

#[test]
fn pop_shape_detected_x86_promotes_to_popreg() {
    // MOV eax, [esi]; ADD esi, 4; MOV [ebp+8], eax; JMP [rip-rel]
    // Same Commit G split as the x64 counterpart above.
    let body = [
        0x8B, 0x06, // MOV eax, [esi]
        0x83, 0xC6, 0x04, // ADD esi, 4
        0x89, 0x45, 0x08, // MOV [ebp+8], eax
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X86),
        Some(VmpSemantic::Popreg)
    );
}

#[test]
fn push_shape_detected_x64_promotes_to_pushimm() {
    // MOV rax, [r15]; SUB r14, 8; MOV [r14], rax; JMP [rip]
    // Commit G split: load-indirect (VIP stream) with no load-disp
    // is `PushImm`, not the deprecated generic `Push` fallback.
    let body = [
        0x49, 0x8B, 0x07, // MOV rax, [r15]
        0x49, 0x83, 0xEE, 0x08, // SUB r14, 8
        0x49, 0x89, 0x06, // MOV [r14], rax
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::PushImm)
    );
}

#[test]
fn vjmp_shape_detected_x64() {
    // MOV rax, [r14]; ADD r14, 8; JMP [rip+disp32]. No CTX store,
    // no VM-stack store -- pattern lands on VJMP rather than POP.
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]
        0x49, 0x83, 0xC6, 0x08, // ADD r14, 8
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Vjmp));
}

// -----------------------------------------------------------------
// Negative / boundary tests.
// -----------------------------------------------------------------

#[test]
fn empty_body_yields_none() {
    assert_eq!(SemanticMatcher::classify(&[], Bitness::X64), None);
}

#[test]
fn random_noise_yields_none() {
    // 32 bytes of noise chosen to avoid any of the fingerprints
    // above (no 0F31/0FA2, no F7 D0-D7, no 9D+C3 window, no
    // 83 C?/E?, no 8B/89 mod=00, no FF /4).
    let body = [0x90u8; 32];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), None);
}

#[test]
fn very_short_body_yields_none() {
    let body = [0x48, 0x8B];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), None);
}

#[test]
fn single_not_and_and_is_not_nand() {
    // Only ONE NOT plus an AND is not enough for a De Morgan pair;
    // NAND requires at least two NOTs. Pinned with `assert_eq!(None)`
    // so a change that mislabels this body as any *other* variant
    // (Vjmp, Push, ...) still fails the test — the earlier
    // `assert_ne!(_, Some(Nand))` would silently pass.
    let body = [
        0x48, 0xF7, 0xD0, // NOT rax
        0x48, 0x21, 0xC8, // AND rax, rcx
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), None);
}

#[test]
fn stray_popfq_without_ret_is_popf() {
    // POPFQ far from any 0xC3 doesn't trigger Vmexit but DOES trigger
    // the new Popf fallback (Commit G). The 0xC3 at index 41 is > 32
    // bytes past the 0x9D, so the Vmexit window check fails.
    let mut body = vec![0x9D];
    body.extend(std::iter::repeat_n(0x90, 40));
    body.push(0xC3);
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Popf));
}

#[test]
fn popreg_is_preferred_over_vjmp_when_store_is_present() {
    // Same shape as `vjmp_shape_detected_x64` but with an added
    // CTX store: Popreg fires (single disp8 < 0x80) and wins.
    // Before Commit G this landed on Pop.
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]
        0x49, 0x83, 0xC6, 0x08, // ADD r14, 8
        0x48, 0x89, 0x45, 0x08, // MOV [rbp+8], rax  <-- CTX store
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::Popreg)
    );
}

#[test]
fn rdtsc_wins_over_push_shape_when_both_present() {
    // Fabricated body containing both a RDTSC opcode pair and a
    // valid push shape: the RDTSC fingerprint runs first.
    let body = [
        0x0F, 0x31, // RDTSC
        0x49, 0x8B, 0x07, // MOV rax, [r15]
        0x49, 0x83, 0xEE, 0x08, // SUB r14, 8
        0x49, 0x89, 0x06, // MOV [r14], rax
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Rdtsc));
}

// -----------------------------------------------------------------
// Enum sanity.
// -----------------------------------------------------------------

#[test]
fn vmp_semantic_is_copy_and_serializable() {
    // Compile-time-ish: the enum must be trivially copyable and
    // survive a JSON round-trip. Any missing derive fails here.
    let s = VmpSemantic::Pop;
    let copy = s;
    assert_eq!(s, copy);
    let json = serde_json::to_string(&s).expect("serialize");
    let back: VmpSemantic = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(s, back);
}

// -----------------------------------------------------------------
// Commit G: 8 P0 matchers.
// -----------------------------------------------------------------

#[test]
fn add_shape_detected_x64() {
    // MOV rax, [r14]      -- load-indirect (VSP)
    // MOV rcx, [r14+8]    -- load-disp (second stack slot)
    // ADD rax, rcx        -- add r,r (opcode 0x01, mod=11)
    // PUSHFQ              -- flag store
    // MOV [r14], rax      -- store-indirect (result back to VSP)
    // JMP [rip+disp32]    -- tail to dispatcher
    let body = [
        0x49, 0x8B, 0x06, 0x49, 0x8B, 0x4E, 0x08, 0x48, 0x01, 0xC8, 0x9C, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00,
        0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Add));
}

#[test]
fn add_missing_pushfq_falls_through_to_pushimm() {
    // Same as `add_shape_detected_x64` but with PUSHFQ removed:
    // is_add_shape fails (`has_pushfq` false), and because the body
    // still has load-indirect + no SUB VSP + store-indirect... it
    // doesn't hit PushImm either (needs SUB VSP). Lands on None.
    let body = [
        0x49, 0x8B, 0x06, 0x49, 0x8B, 0x4E, 0x08, 0x48, 0x01, 0xC8, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00,
        0x00,
    ];
    assert_ne!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Add));
}

#[test]
fn ldd_shape_detected_x64() {
    // MOV rax, [r14]     -- load-indirect 1 (fetch addr from VSP)
    // MOV rcx, [rax]     -- load-indirect 2 (fetch value at addr)
    // MOV [r14], rcx     -- store-indirect (result back to VSP)
    // ADD r14, 0         -- has_add_reg_imm8 (VSP tweak, 0 is fine)
    // JMP [rip+disp32]
    let body = [
        0x49, 0x8B, 0x06, 0x48, 0x8B, 0x08, 0x49, 0x89, 0x0E, 0x49, 0x83, 0xC6, 0x00, 0xFF, 0x25, 0x00, 0x00, 0x00,
        0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Ldd));
}

#[test]
fn str_matcher_matches_ldd_shape_directly() {
    // Ldd wins in classify() (spec), so Str is verified via its
    // internal matcher. Same canonical body as `ldd_shape_detected`
    // -- the extra `!has_store_disp` clause in is_str_shape is also
    // satisfied here.
    let body = [
        0x49, 0x8B, 0x06, 0x48, 0x8B, 0x08, 0x49, 0x89, 0x0E, 0x49, 0x83, 0xC6, 0x00, 0xFF, 0x25, 0x00, 0x00, 0x00,
        0x00,
    ];
    assert!(is_str_shape(&body));
    // Same body plus a CTX store disqualifies Str but not Ldd.
    let body_with_ctx_store = [
        0x49, 0x8B, 0x06, 0x48, 0x8B, 0x08, 0x49, 0x89, 0x0E, 0x49, 0x83, 0xC6, 0x00, 0x48, 0x89, 0x45, 0x08, 0xFF,
        0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert!(!is_str_shape(&body_with_ctx_store));
    assert!(is_ldd_shape(&body_with_ctx_store));
}

#[test]
fn pushreg_shape_detected_x64() {
    // MOV rax, [rbp+8]    -- load-disp (CTX slot)
    // SUB r14, 8          -- SUB VSP
    // MOV [r14], rax      -- store-indirect
    // JMP [rip+disp32]
    let body = [
        0x48, 0x8B, 0x45, 0x08, 0x49, 0x83, 0xEE, 0x08, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::Pushreg)
    );
}

#[test]
fn pushimm_shape_detected_x64() {
    // MOV rax, [r15]      -- load-indirect (VIP stream, no disp)
    // SUB r14, 8          -- SUB VSP
    // MOV [r14], rax      -- store-indirect
    // JMP [rip+disp32]
    // No load-disp anywhere, so PushImm fires ahead of the deprecated
    // generic Push fallback.
    let body = [
        0x49, 0x8B, 0x07, 0x49, 0x83, 0xEE, 0x08, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::PushImm)
    );
}

#[test]
fn pushreg_wins_over_pushimm_when_both_load_shapes_present() {
    // Body carries both a load-indirect AND a load-disp. Under the
    // documented ordering Pushreg fires first (it doesn't care about
    // load-indirect), and PushImm's `!has_load_disp` gate wouldn't
    // fire anyway.
    let body = [
        0x49, 0x8B, 0x07, // MOV rax, [r15]     load-indirect
        0x48, 0x8B, 0x4D, 0x10, // MOV rcx, [rbp+16]  load-disp
        0x49, 0x83, 0xEE, 0x08, // SUB r14, 8
        0x49, 0x89, 0x06, // MOV [r14], rax
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::Pushreg)
    );
}

#[test]
fn popreg_falls_through_to_pop_when_disp_too_large() {
    // Same shape as `popreg_is_preferred_over_vjmp_when_store_is_present`
    // but the CTX-store disp8 is 0x80 (== 128), which is NOT in
    // `[0, 0x80)`. is_popreg_shape's tight guard rejects it and
    // classify() falls through to `Pop`.
    let body = [
        0x49, 0x8B, 0x06, 0x49, 0x83, 0xC6, 0x08, 0x48, 0x89, 0x45, 0x80, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Pop));
}

#[test]
fn popreg_falls_through_to_pop_when_multiple_ctx_stores() {
    // Two CTX stores -- Popreg's "exactly one" clause fails and Pop
    // takes the body.
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]
        0x49, 0x83, 0xC6, 0x08, // ADD r14, 8
        0x48, 0x89, 0x45, 0x08, // MOV [rbp+8], rax
        0x48, 0x89, 0x4D, 0x10, // MOV [rbp+16], rcx  (second CTX store)
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Pop));
}

#[test]
fn vsetvsp_shape_detected() {
    // MOV r14, [r14] alone -- load-indirect only, no adjust, no
    // stores, no dispatcher JMP. The strictest catch-all in the
    // classify() ordering.
    let body = [0x4D, 0x8B, 0x36, 0x90, 0x90, 0x90];
    assert_eq!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::Vsetvsp)
    );
}

#[test]
fn vsetvsp_rejected_when_jump_present() {
    // Add a dispatcher JMP: has_indirect_jmp fires, Vsetvsp guard
    // rejects it, and no other matcher fits -> None.
    let body = [0x4D, 0x8B, 0x36, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), None);
}

#[test]
fn popf_shape_detected_when_no_ret_follows() {
    // POPFQ then dispatcher JMP -- no real x86 RET, so Vmexit is out.
    // Popf runs after every stronger matcher and catches the 0x9D.
    let body = [0x9D, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Popf));
}

#[test]
fn add_wins_over_pushreg_when_both_shapes_could_match() {
    // Body carries both an Add-shape (load-indirect + add r,r +
    // PUSHFQ + store-indirect) AND a PushReg-shape (load-disp +
    // SUB VSP + store-indirect). Add is ranked higher in
    // classify() and takes it.
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]     load-indirect
        0x48, 0x8B, 0x4D, 0x10, // MOV rcx, [rbp+16]  load-disp
        0x48, 0x01, 0xC8, // ADD rax, rcx       add r,r
        0x9C, // PUSHFQ              flag store
        0x49, 0x83, 0xEE, 0x08, // SUB r14, 8
        0x49, 0x89, 0x06, // MOV [r14], rax     store-indirect
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Add));
}

#[test]
fn deprecated_push_never_fires_when_pushimm_would_match() {
    // Any body that would match `is_push_shape` also matches either
    // PushReg (if load-disp present) or PushImm (if not). The
    // deprecated Push fallback is unreachable via classify(); this
    // pins that so a future edit doesn't quietly re-emit it.
    let pushimm_body = [
        0x49, 0x8B, 0x07, 0x49, 0x83, 0xEE, 0x08, 0x49, 0x89, 0x06, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert!(is_push_shape(&pushimm_body));
    assert_ne!(
        SemanticMatcher::classify(&pushimm_body, Bitness::X64),
        Some(VmpSemantic::Push)
    );
}
