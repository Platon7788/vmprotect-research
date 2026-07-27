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
fn pop_shape_detected_x64() {
    // MOV rax, [r14]; ADD r14, 8; MOV [rbp+8], rax; JMP [rip]
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]
        0x49, 0x83, 0xC6, 0x08, // ADD r14, 8
        0x48, 0x89, 0x45, 0x08, // MOV [rbp+8], rax
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Pop));
}

#[test]
fn pop_shape_detected_x86() {
    // MOV eax, [esi]; ADD esi, 4; MOV [ebp+8], eax; JMP [rip-rel]
    let body = [
        0x8B, 0x06, // MOV eax, [esi]
        0x83, 0xC6, 0x04, // ADD esi, 4
        0x89, 0x45, 0x08, // MOV [ebp+8], eax
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X86), Some(VmpSemantic::Pop));
}

#[test]
fn push_shape_detected_x64() {
    // MOV rax, [r15]; SUB r14, 8; MOV [r14], rax; JMP [rip]
    let body = [
        0x49, 0x8B, 0x07, // MOV rax, [r15]
        0x49, 0x83, 0xEE, 0x08, // SUB r14, 8
        0x49, 0x89, 0x06, // MOV [r14], rax
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Push));
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
    // NAND requires at least two NOTs.
    let body = [
        0x48, 0xF7, 0xD0, // NOT rax
        0x48, 0x21, 0xC8, // AND rax, rcx
    ];
    assert_ne!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Nand));
}

#[test]
fn stray_popfq_without_ret_is_not_vmexit() {
    // POPFQ far from any 0xC3 must not trigger VMEXIT.
    let mut body = vec![0x9D];
    body.extend(std::iter::repeat_n(0x90, 40));
    body.push(0xC3);
    assert_ne!(
        SemanticMatcher::classify(&body, Bitness::X64),
        Some(VmpSemantic::Vmexit)
    );
}

#[test]
fn pop_is_preferred_over_vjmp_when_store_is_present() {
    // Same shape as `vjmp_shape_detected_x64` but with an added
    // CTX store: the Pop matcher's `has_store_disp` fires and Pop
    // wins the ordering.
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]
        0x49, 0x83, 0xC6, 0x08, // ADD r14, 8
        0x48, 0x89, 0x45, 0x08, // MOV [rbp+8], rax  <-- CTX store
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(SemanticMatcher::classify(&body, Bitness::X64), Some(VmpSemantic::Pop));
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
