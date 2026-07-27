//! Tests for Commit P's Group E / F / G passes and the outer
//! fixed-point iteration.
//!
//! Split from `junk_stripper_tests.rs` via `#[cfg(test)] #[path]`
//! (see the include in `junk_stripper.rs`) so neither test file goes
//! past the project's 500-line ceiling.

use super::*;
use crate::handler_semantic::{SemanticMatcher, VmpSemantic};

// -----------------------------------------------------------------
// Group E — constant-folding pair cancels.
// -----------------------------------------------------------------

#[test]
fn group_e_add_then_sub_same_imm_cancels() {
    // add rax, 5  ; sub rax, 5    ->  <empty>  (plus trailing ret)
    // 48 83 C0 05 | 48 83 E8 05 | C3
    let body = [0x48, 0x83, 0xC0, 0x05, 0x48, 0x83, 0xE8, 0x05, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), vec![0xC3]);
}

#[test]
fn group_e_sub_then_add_same_imm_cancels() {
    // sub rax, 5  ; add rax, 5
    let body = [0x48, 0x83, 0xE8, 0x05, 0x48, 0x83, 0xC0, 0x05, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), vec![0xC3]);
}

#[test]
fn group_e_double_xor_same_imm_cancels() {
    // xor rax, 5  ; xor rax, 5   -> net-zero
    // 48 83 F0 05 | 48 83 F0 05
    let body = [0x48, 0x83, 0xF0, 0x05, 0x48, 0x83, 0xF0, 0x05, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), vec![0xC3]);
}

#[test]
fn group_e_inc_then_dec_same_reg_cancels() {
    // inc rax = 48 FF C0; dec rax = 48 FF C8
    let body = [0x48, 0xFF, 0xC0, 0x48, 0xFF, 0xC8, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), vec![0xC3]);
}

#[test]
fn group_e_dec_then_inc_same_reg_cancels() {
    let body = [0x48, 0xFF, 0xC8, 0x48, 0xFF, 0xC0, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), vec![0xC3]);
}

#[test]
fn group_e_double_neg_cancels() {
    // neg rax = 48 F7 D8; neg rax = 48 F7 D8
    let body = [0x48, 0xF7, 0xD8, 0x48, 0xF7, 0xD8, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), vec![0xC3]);
}

#[test]
fn group_e_double_not_cancels() {
    // not rax = 48 F7 D0; not rax = 48 F7 D0
    let body = [0x48, 0xF7, 0xD0, 0x48, 0xF7, 0xD0, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), vec![0xC3]);
}

#[test]
fn group_e_add_k1_add_k2_summing_to_zero_cancels() {
    // add rax, 5   (48 83 C0 05)
    // add rax, -5  (48 83 C0 FB)
    let body = [0x48, 0x83, 0xC0, 0x05, 0x48, 0x83, 0xC0, 0xFB, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), vec![0xC3]);
}

#[test]
fn group_e_add_sub_across_harmless_intermediate_still_cancels() {
    // add rax, 5   ; xor rcx, rcx (writes rcx, reads rcx, touches flags — no
    //              ; memory, no branch, no rax write) ; sub rax, 5
    //
    // XOR is opcode 0x31 (r/m,r); my decoder marks that as Kind::Other but
    // still tracks writes/reads. We use an operand shape my decoder is
    // known to handle: `sub rcx, rcx` via 0x83 /5 imm8=0 form is dropped
    // by Group C; use `mov rcx, rdx` instead — reg-reg mov writes rcx,
    // reads rdx, and passes the "no rax write" filter.
    //
    // mov rcx, rdx = 48 89 D1 (0x89 mod=11 reg=010 rdx rm=001 rcx)
    let body = [
        0x48, 0x83, 0xC0, 0x05, // add rax, 5
        0x48, 0x89, 0xD1, // mov rcx, rdx
        0x48, 0x83, 0xE8, 0x05, // sub rax, 5
        0xC3,
    ];
    // The add/sub cancel; mov rcx, rdx survives. Group G may or may not
    // strip the surviving mov (rcx is live per R_ALL initial live-out).
    let expected = [0x48, 0x89, 0xD1, 0xC3];
    assert_eq!(strip_junk(&body, Bitness::X64), expected.to_vec());
}

#[test]
fn group_e_no_strip_when_target_reg_written_between() {
    // add rax, 5   ; add rax, 3 (writes rax with a value we don't cancel)
    // ; sub rax, 5
    //
    // The intermediate add writes rax with an unrelated delta, so the
    // outer sub no longer sees "rax + 5" — folding would change the
    // final rax value.
    let body = [
        0x48, 0x83, 0xC0, 0x05, // add rax, 5
        0x48, 0x83, 0xC0, 0x03, // add rax, 3
        0x48, 0x83, 0xE8, 0x05, // sub rax, 5
        0xC3,
    ];
    assert_eq!(strip_junk(&body, Bitness::X64), body.to_vec());
}

#[test]
fn group_e_no_strip_across_memory_op() {
    // add rax, 5   ; mov rbx, [rcx]  ; sub rax, 5
    // Memory access between anchor and cancel is a barrier.
    let body = [
        0x48, 0x83, 0xC0, 0x05, // add rax, 5
        0x48, 0x8B, 0x19, // mov rbx, [rcx]
        0x48, 0x83, 0xE8, 0x05, // sub rax, 5
        0xC3,
    ];
    // Group F does strip the mov rbx, [rcx] because rbx is not read again
    // before ret (whose live-in is R_ALL, but Group F walks forward and
    // there's no next write to rbx — anchor is preserved).
    //
    // The relevant assertion is: the add/sub pair survives.
    let out = strip_junk(&body, Bitness::X64);
    assert!(
        out.windows(4).any(|w| w == [0x48, 0x83, 0xC0, 0x05]),
        "add rax, 5 must survive; got {:02X?}",
        out
    );
    assert!(
        out.windows(4).any(|w| w == [0x48, 0x83, 0xE8, 0x05]),
        "sub rax, 5 must survive; got {:02X?}",
        out
    );
}

#[test]
fn group_e_no_strip_when_window_exceeded() {
    // Anchor and cancel separated by 42 bytes of `mov [rcx], rdx` — a
    // memory store, which is BOTH a Group E barrier (memory op) AND
    // impossible for Group F to prune (memory_store side effect). So
    // the intermediates persist across fixed-point iterations and E's
    // 32-byte window filter cannot be re-enabled.
    let mut body = vec![0x48, 0x83, 0xC0, 0x05]; // add rax, 5
    for _ in 0..14 {
        body.extend_from_slice(&[0x48, 0x89, 0x11]); // mov [rcx], rdx
    }
    body.extend_from_slice(&[0x48, 0x83, 0xE8, 0x05]); // sub rax, 5
    body.push(0xC3);
    let out = strip_junk(&body, Bitness::X64);
    // The add and sub must both survive somewhere in the output.
    assert!(
        out.windows(4).any(|w| w == [0x48, 0x83, 0xC0, 0x05]),
        "add rax, 5 must survive; got {:02X?}",
        out
    );
    assert!(
        out.windows(4).any(|w| w == [0x48, 0x83, 0xE8, 0x05]),
        "sub rax, 5 must survive; got {:02X?}",
        out
    );
}

// -----------------------------------------------------------------
// Group F — dead-store elimination.
// -----------------------------------------------------------------

#[test]
fn group_f_dead_mov_reg_mem_stripped() {
    // mov rax, [rbx]  ; mov rax, [rcx]  ; ret
    // 48 8B 03        | 48 8B 01        | C3
    // The first mov's write to rax is dead — overridden with no
    // intermediate read.
    let body = [0x48, 0x8B, 0x03, 0x48, 0x8B, 0x01, 0xC3];
    let out = strip_junk(&body, Bitness::X64);
    assert_eq!(out, vec![0x48, 0x8B, 0x01, 0xC3]);
}

#[test]
fn group_f_dead_lea_stripped() {
    // lea rax, [rbx]  ; lea rax, [rcx]  ; ret
    // 48 8D 03        | 48 8D 01        | C3
    let body = [0x48, 0x8D, 0x03, 0x48, 0x8D, 0x01, 0xC3];
    let out = strip_junk(&body, Bitness::X64);
    assert_eq!(out, vec![0x48, 0x8D, 0x01, 0xC3]);
}

#[test]
fn group_f_preserved_when_reg_read_between_writes() {
    // mov rax, [rbx]  ; mov [rcx], rax  ; mov rax, [rdx]  ; ret
    // The middle mov stores rax to memory — reads rax — so the first
    // write is genuinely consumed and must be preserved.
    let body = [
        0x48, 0x8B, 0x03, // mov rax, [rbx]
        0x48, 0x89, 0x01, // mov [rcx], rax
        0x48, 0x8B, 0x02, // mov rax, [rdx]
        0xC3,
    ];
    let out = strip_junk(&body, Bitness::X64);
    assert_eq!(out, body.to_vec(), "unexpected strip: {:02X?}", out);
}

#[test]
fn group_f_two_dead_writes_both_stripped_via_chain() {
    // Three consecutive movs to rax — first two are dead, last survives.
    let body = [
        0x48, 0x8B, 0x03, // mov rax, [rbx]  (dead)
        0x48, 0x8B, 0x01, // mov rax, [rcx]  (dead)
        0x48, 0x8B, 0x02, // mov rax, [rdx]  (kept — rax live at ret)
        0xC3,
    ];
    let out = strip_junk(&body, Bitness::X64);
    assert_eq!(out, vec![0x48, 0x8B, 0x02, 0xC3]);
}

// -----------------------------------------------------------------
// Group G — backward-liveness sweep.
// -----------------------------------------------------------------

#[test]
fn group_g_removes_dead_not_reg_overridden_by_later_write() {
    // NOT rax leaves flags untouched (unlike NEG), so it's a rare
    // Kind::NotReg that Group F doesn't handle (F only strips
    // MovRegDst/LeaRegDst). Group G is the mop-up.
    //
    // not rax        (48 F7 D0)  -- writes rax, reads rax, no flags
    // mov rax, [rbx] (48 8B 03)  -- fully overrides rax before ret
    // ret
    //
    // Backward pass sees `not rax`'s write is dead (mov rax, [rbx]
    // will overwrite it before ret's R_ALL live-in kicks in).
    let body = [0x48, 0xF7, 0xD0, 0x48, 0x8B, 0x03, 0xC3];
    let out = strip_junk(&body, Bitness::X64);
    assert_eq!(out, vec![0x48, 0x8B, 0x03, 0xC3]);
}

#[test]
fn group_g_keeps_write_when_reg_used_downstream() {
    // mov rax, [rbx]  ; mov rcx, rax  ; ret
    // rcx = f(rax) — the mov's write to rax is consumed by mov rcx,rax,
    // so the load must be preserved even though rax isn't itself in
    // the final store.
    let body = [
        0x48, 0x8B, 0x03, // mov rax, [rbx]
        0x48, 0x89, 0xC1, // mov rcx, rax
        0xC3,
    ];
    let out = strip_junk(&body, Bitness::X64);
    assert_eq!(out, body.to_vec());
}

// -----------------------------------------------------------------
// Fixed-point iteration — one pass exposes work for the next.
// -----------------------------------------------------------------

#[test]
fn fixed_point_group_a_unlocks_e_unlocks_f() {
    // mov rax, rax    (A — junk)
    // add rax, 5      (E anchor)
    // mov rbx, rbx    (A — junk)
    // sub rax, 5      (E cancel — reachable only after A strips the mov r,r)
    // mov rax, [rcx]  (F anchor — dead)
    // mov rax, [rdx]  (F cancel — overrides)
    // ret
    //
    // After the pipeline: all E/F junk removed; only `mov rax, [rdx]; ret`.
    let body = [
        0x48, 0x89, 0xC0, // mov rax, rax
        0x48, 0x83, 0xC0, 0x05, // add rax, 5
        0x48, 0x89, 0xDB, // mov rbx, rbx
        0x48, 0x83, 0xE8, 0x05, // sub rax, 5
        0x48, 0x8B, 0x01, // mov rax, [rcx]
        0x48, 0x8B, 0x02, // mov rax, [rdx]
        0xC3,
    ];
    let out = strip_junk(&body, Bitness::X64);
    assert_eq!(out, vec![0x48, 0x8B, 0x02, 0xC3]);
}

#[test]
fn fixed_point_group_e_unlocks_group_b() {
    // push rax; add rax, 5; sub rax, 5; pop rax; ret
    //
    // Iter 1: Group E cancels add/sub -> push rax; pop rax; ret.
    // Iter 2: Group B strips the now-adjacent push/pop -> ret.
    // Iter 3: fixed point.
    let body = [
        0x50, // push rax
        0x48, 0x83, 0xC0, 0x05, // add rax, 5
        0x48, 0x83, 0xE8, 0x05, // sub rax, 5
        0x58, // pop rax
        0xC3, // ret
    ];
    let out = strip_junk(&body, Bitness::X64);
    assert_eq!(out, vec![0xC3]);
}

#[test]
fn fixed_point_iteration_cap_limits_work() {
    // Same body as above — full run collapses to `ret`. With a cap of
    // 1 iteration we should see the intermediate `push rax; pop rax;
    // ret` shape (Group E ran in iter 1, but Group B needs an iter 2
    // to notice the now-adjacent pair). Proves the cap actually
    // truncates the loop rather than silently over-running.
    let body = [
        0x50, // push rax
        0x48, 0x83, 0xC0, 0x05, // add rax, 5
        0x48, 0x83, 0xE8, 0x05, // sub rax, 5
        0x58, // pop rax
        0xC3, // ret
    ];
    let out_1 = strip_junk_with_limits(&body, Bitness::X64, 1);
    assert_eq!(out_1, vec![0x50, 0x58, 0xC3]);
    let out_2 = strip_junk_with_limits(&body, Bitness::X64, 2);
    assert_eq!(out_2, vec![0xC3]);
}

#[test]
fn fixed_point_max_iters_zero_returns_input_verbatim() {
    // Zero-iter cap must return the input verbatim without panicking.
    // Guards the future refactor risk of turning the outer `for` loop
    // into a `while` that assumes at least one iteration.
    let body = [
        0x48, 0x83, 0xC0, 0x05, // add rax, 5
        0x48, 0x83, 0xE8, 0x05, // sub rax, 5
        0xC3,
    ];
    let out = strip_junk_with_limits(&body, Bitness::X64, 0);
    assert_eq!(out, body.to_vec());
}

// -----------------------------------------------------------------
// Integration — Group A/C/D + E + F all firing between the real
// load/adjust/store steps of a Popreg handler shape must not defeat
// the semantic matcher. This is the Commit-P extension of
// `junk_inserted_pop_shape_still_classifies_as_pop_after_strip`.
// -----------------------------------------------------------------

#[test]
fn junk_inserted_pop_shape_with_all_groups_still_classifies() {
    // Layout — real steps interleaved with all four kinds of junk the
    // Commit-P pipeline handles:
    //
    //   [real load]   mov rax, [r14]
    //   [Group A]     nop
    //   [Group A]     mov rax, rax
    //   [Group C]     add rax, 0
    //   [Group E]     add rcx, 5           ; anchor
    //   [real adj]    add r14, 8           ; touches r14, not rcx/rax
    //   [Group E]     sub rcx, 5           ; cancel
    //   [Group F]     mov rbx, [r14]       ; dead — killed below
    //   [Group F]     mov rbx, [rdx]       ; live at ret via R_ALL
    //   [real store]  mov [rbp+8], rax
    //   [real jmp]    jmp [rip+0]
    //
    // Post-strip, the real load / adjust / store / jmp all survive,
    // so the matcher still sees Popreg.
    let body = [
        0x49, 0x8B, 0x06, // mov rax, [r14]       -- real load
        0x90, // nop                                 -- A
        0x48, 0x89, 0xC0, // mov rax, rax          -- A
        0x48, 0x83, 0xC0, 0x00, // add rax, 0     -- C
        0x48, 0x83, 0xC1, 0x05, // add rcx, 5     -- E anchor
        0x49, 0x83, 0xC6, 0x08, // add r14, 8     -- real adjust
        0x48, 0x83, 0xE9, 0x05, // sub rcx, 5     -- E cancel
        0x49, 0x8B, 0x1E, // mov rbx, [r14]       -- F dead
        0x48, 0x8B, 0x1A, // mov rbx, [rdx]       -- F kept
        0x48, 0x89, 0x45, 0x08, // mov [rbp+8], rax -- real store
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp [rip+0]
    ];
    let stripped = strip_junk(&body, Bitness::X64);
    assert_eq!(
        SemanticMatcher::classify(&stripped, Bitness::X64),
        Some(VmpSemantic::Popreg),
        "stripped body must still classify as Popreg; stripped: {:02X?}",
        stripped
    );
    // Sanity: the pipeline actually stripped bytes.
    assert!(stripped.len() < body.len(), "expected stripping to shorten body");
}
