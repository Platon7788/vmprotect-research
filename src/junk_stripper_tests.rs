//! Unit tests for `junk_stripper`.
//!
//! Split from `junk_stripper.rs` via `#[cfg(test)] #[path]` so the impl
//! file stays under the project's 500-line ceiling (see `CLAUDE.md`).
//! Compiled only under `#[cfg(test)]`.

use super::*;
use crate::handler_semantic::{SemanticMatcher, VmpSemantic};

// -----------------------------------------------------------------
// Boundary conditions.
// -----------------------------------------------------------------

#[test]
fn empty_input_produces_empty_output() {
    assert_eq!(strip_junk(&[], Bitness::X64), Vec::<u8>::new());
    assert_eq!(strip_junk(&[], Bitness::X86), Vec::<u8>::new());
}

#[test]
fn single_byte_input_is_preserved_when_not_junk() {
    // 0xC3 (RET) is not junk.
    assert_eq!(strip_junk(&[0xC3], Bitness::X64), vec![0xC3]);
}

#[test]
fn very_short_input_is_safe() {
    // Two-byte input, neither byte matching any junk pattern.
    assert_eq!(strip_junk(&[0xC3, 0x00], Bitness::X64), vec![0xC3, 0x00]);
}

// -----------------------------------------------------------------
// Group A — same-register no-ops.
// -----------------------------------------------------------------

#[test]
fn group_a_single_byte_nop_is_stripped() {
    assert_eq!(strip_junk(&[0x90, 0xC3], Bitness::X64), vec![0xC3]);
}

#[test]
fn group_a_multibyte_nop_is_stripped() {
    // nop dword ptr [rax]  =  0F 1F 00
    assert_eq!(strip_junk(&[0x0F, 0x1F, 0x00, 0xC3], Bitness::X64), vec![0xC3]);
}

#[test]
fn group_a_mov_reg_reg_same_is_stripped_x64() {
    // mov rax, rax  =  48 89 C0
    assert_eq!(strip_junk(&[0x48, 0x89, 0xC0, 0xC3], Bitness::X64), vec![0xC3]);
}

#[test]
fn group_a_mov_reg_reg_different_is_kept() {
    // mov rax, rcx  =  48 89 C8   (reg=1 rcx, rm=0 rax)  -- NOT same reg.
    let body = [0x48, 0x89, 0xC8, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), body.to_vec());
}

#[test]
fn group_a_xchg_reg_reg_same_is_stripped() {
    // xchg rax, rax  =  48 87 C0
    assert_eq!(strip_junk(&[0x48, 0x87, 0xC0, 0xC3], Bitness::X64), vec![0xC3]);
}

#[test]
fn group_a_lea_reg_bracket_reg_is_stripped() {
    // lea rax, [rax]  =  48 8D 00
    assert_eq!(strip_junk(&[0x48, 0x8D, 0x00, 0xC3], Bitness::X64), vec![0xC3]);
}

#[test]
fn group_a_lea_reg_bracket_reg_plus_zero_disp8_is_stripped() {
    // lea rax, [rax+0]  =  48 8D 40 00
    assert_eq!(strip_junk(&[0x48, 0x8D, 0x40, 0x00, 0xC3], Bitness::X64), vec![0xC3]);
}

#[test]
fn group_a_lea_reg_bracket_reg_plus_zero_disp32_is_stripped() {
    // lea rax, [rax+0x00000000]  =  48 8D 80 00 00 00 00
    let body = [0x48, 0x8D, 0x80, 0x00, 0x00, 0x00, 0x00, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), vec![0xC3]);
}

#[test]
fn group_a_lea_reg_bracket_reg_plus_nonzero_disp8_is_kept() {
    // lea rax, [rax+1] — real effect, must not be stripped.
    let body = [0x48, 0x8D, 0x40, 0x01, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), body.to_vec());
}

#[test]
fn group_a_or_reg_reg_same_is_stripped() {
    // or rax, rax  =  48 09 C0
    assert_eq!(strip_junk(&[0x48, 0x09, 0xC0, 0xC3], Bitness::X64), vec![0xC3]);
}

#[test]
fn group_a_and_reg_reg_same_is_stripped() {
    // and rax, rax  =  48 21 C0
    assert_eq!(strip_junk(&[0x48, 0x21, 0xC0, 0xC3], Bitness::X64), vec![0xC3]);
}

#[test]
fn group_a_mov_r8_r8_extended_reg_is_stripped() {
    // mov r8, r8  =  4D 89 C0  (REX.R and REX.B both set, so reg==rm still means same physical reg).
    assert_eq!(strip_junk(&[0x4D, 0x89, 0xC0, 0xC3], Bitness::X64), vec![0xC3]);
}

#[test]
fn group_a_mov_rax_r8_is_kept() {
    // mov rax, r8  =  4C 89 C0  (REX.R=1 lifts reg to r8, REX.B=0 keeps rm as rax) -- NOT same reg.
    let body = [0x4C, 0x89, 0xC0, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), body.to_vec());
}

#[test]
fn group_a_mov_reg_reg_same_stripped_x86_without_rex() {
    // mov eax, eax  =  89 C0
    assert_eq!(strip_junk(&[0x89, 0xC0, 0xC3], Bitness::X86), vec![0xC3]);
}

// -----------------------------------------------------------------
// Group B — push/pop pairs.
// -----------------------------------------------------------------

#[test]
fn group_b_adjacent_push_pop_same_reg_is_stripped() {
    // push rax; pop rax  =  50 58
    assert_eq!(strip_junk(&[0x50, 0x58, 0xC3], Bitness::X64), vec![0xC3]);
}

#[test]
fn group_b_adjacent_push_pop_different_reg_is_kept() {
    // push rax; pop rcx  =  50 59  -- moves rax into rcx, must be kept.
    let body = [0x50, 0x59, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), body.to_vec());
}

#[test]
fn group_b_push_pop_with_intervening_use_is_kept() {
    // push rax; mov [rcx], rax; pop rax
    //
    // The intervening MOV *stores* rax to memory, so rax is genuinely
    // consumed between the push and pop — the push/pop preserves the
    // caller's rax across the store, which is real work. Any of
    // Groups A-G stripping either half of the pair (or the store)
    // would change semantics.
    //
    // Note: this test used to spell the intervening instruction as
    // `mov rax, [rbx]` (a load), but Group F (Commit P) correctly
    // identifies that variant as a dead write killed by the following
    // pop, so we switched to a store form to keep the "intervening
    // real use" invariant this test guards.
    let body = [
        0x50, // push rax
        0x48, 0x89, 0x01, // mov [rcx], rax
        0x58, // pop rax
        0xC3,
    ];
    assert_eq!(strip_junk(&body, Bitness::X64), body.to_vec());
}

#[test]
fn group_b_push_pop_with_intervening_junk_reduces_to_empty() {
    // push rax; mov rax, rax (junk); pop rax  -- phase 1 removes the
    // junk, phase 2 sees adjacent push/pop, strips both.
    let body = [
        0x50, // push rax
        0x48, 0x89, 0xC0, // mov rax, rax (junk)
        0x58, // pop rax
        0xC3,
    ];
    assert_eq!(strip_junk(&body, Bitness::X64), vec![0xC3]);
}

#[test]
fn group_b_nested_push_pop_pairs_reduce_via_fixed_point() {
    // push rax; push rax; pop rax; pop rax  ->  removed entirely.
    let body = [0x50, 0x50, 0x58, 0x58, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), vec![0xC3]);
}

#[test]
fn group_b_push_pop_extended_regs() {
    // push r8; pop r8  =  41 50 41 58
    let body = [0x41, 0x50, 0x41, 0x58, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), vec![0xC3]);
}

// -----------------------------------------------------------------
// Group C — trivial arithmetic folds.
// -----------------------------------------------------------------

#[test]
fn group_c_add_reg_zero_is_stripped() {
    // add rax, 0  =  48 83 C0 00
    assert_eq!(strip_junk(&[0x48, 0x83, 0xC0, 0x00, 0xC3], Bitness::X64), vec![0xC3]);
}

#[test]
fn group_c_sub_reg_zero_is_stripped() {
    // sub rax, 0  =  48 83 E8 00
    assert_eq!(strip_junk(&[0x48, 0x83, 0xE8, 0x00, 0xC3], Bitness::X64), vec![0xC3]);
}

#[test]
fn group_c_and_reg_minus_one_is_stripped() {
    // and rax, -1  =  48 83 E0 FF
    assert_eq!(strip_junk(&[0x48, 0x83, 0xE0, 0xFF, 0xC3], Bitness::X64), vec![0xC3]);
}

#[test]
fn group_c_or_reg_zero_is_stripped() {
    // or rax, 0  =  48 83 C8 00
    assert_eq!(strip_junk(&[0x48, 0x83, 0xC8, 0x00, 0xC3], Bitness::X64), vec![0xC3]);
}

#[test]
fn group_c_add_reg_five_is_kept() {
    // add rax, 5  =  48 83 C0 05  -- NOT junk (non-zero imm).
    let body = [0x48, 0x83, 0xC0, 0x05, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), body.to_vec());
}

#[test]
fn group_c_xor_reg_zero_is_kept() {
    // xor rax, 0  =  48 83 F0 00  (subop 6). We deliberately do not
    // fold XOR (a XOR 0 is a no-op but is not on the requested list).
    let body = [0x48, 0x83, 0xF0, 0x00, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), body.to_vec());
}

// -----------------------------------------------------------------
// Group D — stray segment prefixes.
// -----------------------------------------------------------------

#[test]
fn group_d_stray_segment_prefix_before_nop_is_stripped() {
    // FS: NOP  ->  NOP (segment prefix is junk in this context, but we
    // also strip the trailing NOP as junk; result is empty except for
    // the terminating RET).
    assert_eq!(strip_junk(&[0x64, 0x90, 0xC3], Bitness::X64), vec![0xC3]);
}

#[test]
fn group_d_segment_prefix_before_memory_op_is_kept() {
    // FS: mov rax, [rbx]  =  64 48 8B 03  -- real memory access, keep.
    let body = [0x64, 0x48, 0x8B, 0x03, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), body.to_vec());
}

#[test]
fn group_d_segment_prefix_before_reg_reg_op_is_stripped() {
    // ES: mov rax, rax  =  26 48 89 C0
    // The segment prefix is stripped (ES: has no effect on reg-reg mov),
    // then the mov rax, rax is stripped as Group A.
    assert_eq!(strip_junk(&[0x26, 0x48, 0x89, 0xC0, 0xC3], Bitness::X64), vec![0xC3]);
}

// -----------------------------------------------------------------
// Sanity — real (non-junk) instructions MUST NOT be touched by any
// of Groups A-D. Named `sanity_*` (not `group_e_*`) because Commit P
// introduced a genuine Group E for constant-folding pair cancels,
// tests for which live in the sibling `junk_stripper_folds_tests.rs`.
// -----------------------------------------------------------------

#[test]
fn sanity_real_add_with_nonzero_imm_is_kept() {
    // add rax, 5 — non-zero imm, real effect.
    let body = [0x48, 0x83, 0xC0, 0x05, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), body.to_vec());
}

#[test]
fn sanity_real_mov_from_memory_is_kept() {
    // mov rax, [rbx]  =  48 8B 03  -- memory op, keep.
    //
    // NB: on the enhanced Commit-P pipeline this is still preserved
    // because Group F won't strip a lone `mov r, [mem]; ret`: the
    // ret's live-in is R_ALL, so rax IS live after the load and the
    // load survives.
    let body = [0x48, 0x8B, 0x03, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), body.to_vec());
}

#[test]
fn sanity_lock_prefix_is_kept() {
    // lock or [rbx], rax  =  F0 48 09 03  -- memory barrier, keep entire form.
    let body = [0xF0, 0x48, 0x09, 0x03, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), body.to_vec());
}

// -----------------------------------------------------------------
// Integration — Group A/C junk BETWEEN load/adjust/store steps of a
// real POP handler shape must not defeat the semantic matcher.
// -----------------------------------------------------------------

#[test]
fn junk_inserted_pop_shape_still_classifies_as_pop_after_strip() {
    // Same as `pop_shape_detected_x64` in handler_semantic_tests, but
    // with 3 junk instructions sprinkled between the real steps.
    let body = [
        0x49, 0x8B, 0x06, // MOV rax, [r14]           <-- load
        0x90, // NOP                                   <-- junk
        0x48, 0x89, 0xC0, // MOV rax, rax             <-- junk
        0x49, 0x83, 0xC6, 0x08, // ADD r14, 8         <-- adjust
        0x48, 0x83, 0xC0, 0x00, // ADD rax, 0         <-- junk
        0x48, 0x89, 0x45, 0x08, // MOV [rbp+8], rax   <-- store
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // JMP [rip+0]
    ];
    let stripped = strip_junk(&body, Bitness::X64);
    assert_eq!(
        SemanticMatcher::classify(&stripped, Bitness::X64),
        Some(VmpSemantic::Popreg),
        "stripped body must still classify as Popreg; stripped bytes: {:02X?}",
        stripped
    );
}

#[test]
fn junk_inserted_pop_shape_still_classifies_before_and_after_strip() {
    // The matcher is presence-anywhere so it may already classify the
    // pre-strip body; the important assertion is that stripping does
    // not accidentally REMOVE the classification signal.
    let body = [
        0x49, 0x8B, 0x06, 0x90, // extra nop
        0x49, 0x83, 0xC6, 0x08, 0x48, 0x89, 0x45, 0x08, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    let stripped = strip_junk(&body, Bitness::X64);
    let pre = SemanticMatcher::classify(&body, Bitness::X64);
    let post = SemanticMatcher::classify(&stripped, Bitness::X64);
    assert_eq!(pre, Some(VmpSemantic::Popreg));
    assert_eq!(post, Some(VmpSemantic::Popreg));
}

// -----------------------------------------------------------------
// x86 bitness — 0x40..0x4F must NOT be treated as REX on x86.
// -----------------------------------------------------------------

#[test]
fn x86_inc_reg_before_nonjunk_is_kept() {
    // On x86, 0x40 is INC EAX — a real one-byte instruction, not a
    // prefix. Followed by 0x89 0xC0 (mov eax, eax, which IS junk on
    // its own), the stripper must NOT swallow 0x40 as part of a
    // "mov eax, eax with REX" form.
    let body = [0x40, 0x89, 0xC0, 0xC3];
    let stripped = strip_junk(&body, Bitness::X86);
    // The 0x89 0xC0 pair is still same-reg junk on x86 — stripped.
    // But the leading 0x40 (INC EAX) must remain.
    assert_eq!(stripped, vec![0x40, 0xC3]);
}

#[test]
fn x86_dec_reg_is_kept_as_real_instruction() {
    // 0x48 = DEC EAX on x86. Followed by real bytes it must be kept
    // as its own 1-byte instruction rather than absorbed as a REX prefix.
    let body = [0x48, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X86), body.to_vec());
}

// -----------------------------------------------------------------
// Sanity: stripped output must never grow past the input.
// -----------------------------------------------------------------

#[test]
fn stripped_body_never_grows() {
    // Handful of varied inputs — result length ≤ input length.
    for body in [
        vec![0x90u8; 16],
        vec![0x48, 0x89, 0xC0, 0x48, 0x89, 0xC1, 0x48, 0x83, 0xC0, 0x00],
        vec![0x50, 0x58, 0x51, 0x59, 0x52, 0x5A, 0xC3],
        vec![0xC3],
    ] {
        let out = strip_junk(&body, Bitness::X64);
        assert!(
            out.len() <= body.len(),
            "stripped body grew: in {:?} out {:?}",
            body,
            out
        );
    }
}
