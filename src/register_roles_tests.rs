//! Unit tests for `register_roles`.
//!
//! Split from `register_roles.rs` via `#[cfg(test)] #[path = ...] mod
//! tests;` so the impl file stays under the project's 500-line ceiling
//! (see `CLAUDE.md`). Compiled only under `#[cfg(test)]`.
//!
//! Each test constructs synthetic handler bodies whose byte encoding is
//! known to touch a specific register, then asserts the voter's
//! decision. The encoding cheat-sheet used across the tests:
//!
//! - `MOV rax, [r14]`  = `49 8B 06` (REX.WB, opcode 8B, mod=00 rm=6)
//! - `MOV [r14], rax`  = `49 89 06`
//! - `ADD r15, imm8`   = `49 83 C7 <imm>` (mod=11 /0 rm=7 + REX.B)
//! - `SUB r15, imm8`   = `49 83 EF <imm>` (mod=11 /5 rm=7 + REX.B)
//! - `XOR rbx, imm32`  = `48 81 F3 <imm32>` (mod=11 /6 rm=3)
//! - `MOV eax, [ebx]`  = `8B 03` (no REX, mod=00 rm=3)
//! - `MOV [ebx], eax`  = `89 03`

use super::*;

/// Handler body: `MOV rax, [r14]; MOV [r14], rax; JMP [rip]`. r14 is
/// touched twice as an indirect base — pure VSP-shape signal, no VIP
/// or VKEY signal.
fn vsp_r14_body() -> Vec<u8> {
    vec![
        0x49, 0x8B, 0x06, // MOV rax, [r14]
        0x49, 0x89, 0x06, // MOV [r14], rax
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // JMP [rip+0]
    ]
}

/// Handler body: `ADD r15, 4; MOV rax, [r15]; JMP [rip]`. Pure VIP
/// shape — inc-by-imm on r15, indirect load through r15, never a
/// store through r15.
fn vip_r15_body() -> Vec<u8> {
    vec![
        0x49, 0x83, 0xC7, 0x04, // ADD r15, 4
        0x49, 0x8B, 0x07, // MOV rax, [r15]
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ]
}

/// Handler body: `XOR rbx, 0xDEADBEEF; JMP [rip]`. Pure VKEY shape.
fn vkey_rbx_body() -> Vec<u8> {
    vec![
        0x48, 0x81, 0xF3, 0xEF, 0xBE, 0xAD, 0xDE, // XOR rbx, 0xDEADBEEF
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    ]
}

// ---------------------------------------------------------------------
// Voter behaviour
// ---------------------------------------------------------------------

#[test]
fn vsp_detected_when_r14_dominates_indirect_accesses() {
    let handlers: Vec<Vec<u8>> = (0..5).map(|_| vsp_r14_body()).collect();
    let roles = analyse_handlers(&handlers, Bitness::X64);
    assert_eq!(roles.vsp, Some(Register::R14));
    assert_eq!(roles.handlers_seen, 5);
    // Q: every handler agrees on r14 as the VSP, so cross-handler
    // consistency is unity.
    assert!(
        (roles.vsp_consistency - 1.0).abs() < f64::EPSILON,
        "vsp_consistency={} but every handler dominates on r14",
        roles.vsp_consistency
    );
}

#[test]
fn vip_detected_when_r15_is_incremented_and_loaded_from() {
    let handlers: Vec<Vec<u8>> = (0..5).map(|_| vip_r15_body()).collect();
    let roles = analyse_handlers(&handlers, Bitness::X64);
    assert_eq!(roles.vip, Some(Register::R15));
    assert!(
        (roles.vip_consistency - 1.0).abs() < f64::EPSILON,
        "vip_consistency={} but every handler dominates on r15",
        roles.vip_consistency
    );
}

#[test]
fn vkey_detected_when_rbx_is_xored_with_imm() {
    let handlers: Vec<Vec<u8>> = (0..5).map(|_| vkey_rbx_body()).collect();
    let roles = analyse_handlers(&handlers, Bitness::X64);
    assert_eq!(roles.vkey, Some(Register::Rbx));
    assert!(
        (roles.vkey_consistency - 1.0).abs() < f64::EPSILON,
        "vkey_consistency={} but every handler dominates on rbx",
        roles.vkey_consistency
    );
}

#[test]
fn combined_signal_populates_all_three_roles() {
    // Q: with the cross-handler consistency gate, "combined signal" must
    // be a single handler exhibiting ALL three shapes at once — a
    // 5+5+5 corpus split across three shapes now fails the >=60%
    // per-handler agreement bar for each role (each shape appears in
    // only a third of handlers). This mirrors real VMP samples where
    // every handler references VSP/VIP even when it only writes VKEY.
    let combined_body: Vec<u8> = {
        let mut b = vsp_r14_body();
        b.extend(vip_r15_body());
        b.extend(vkey_rbx_body());
        b
    };
    let handlers: Vec<Vec<u8>> = (0..5).map(|_| combined_body.clone()).collect();
    let roles = analyse_handlers(&handlers, Bitness::X64);
    assert_eq!(roles.vsp, Some(Register::R14));
    assert_eq!(roles.vip, Some(Register::R15));
    assert_eq!(roles.vkey, Some(Register::Rbx));
    assert_eq!(roles.handlers_seen, 5);
    assert!(
        (roles.vsp_consistency - 1.0).abs() < f64::EPSILON,
        "vsp_consistency={} but every handler carries the same r14 VSP shape",
        roles.vsp_consistency
    );
    assert!(
        (roles.vip_consistency - 1.0).abs() < f64::EPSILON,
        "vip_consistency={} but every handler carries the same r15 VIP shape",
        roles.vip_consistency
    );
    assert!(
        (roles.vkey_consistency - 1.0).abs() < f64::EPSILON,
        "vkey_consistency={} but every handler carries the same rbx VKEY shape",
        roles.vkey_consistency
    );
}

// ---------------------------------------------------------------------
// Insufficient / ambiguous signal — voter must return None
// ---------------------------------------------------------------------

#[test]
fn insufficient_signal_yields_all_none() {
    // Single handler with a bare RET — no recognised shape at all.
    let handlers = vec![vec![0xC3]];
    let roles = analyse_handlers(&handlers, Bitness::X64);
    assert_eq!(roles.vsp, None);
    assert_eq!(roles.vip, None);
    assert_eq!(roles.vkey, None);
    assert_eq!(roles.handlers_seen, 1);
}

#[test]
fn empty_handler_set_yields_default() {
    let roles = analyse_handlers(&[], Bitness::X64);
    assert_eq!(roles, RegisterRoles::default());
}

#[test]
fn ambiguous_vsp_tie_between_r14_and_r15_yields_none() {
    // Each handler touches r14 AND r15 equally as indirect bases; no
    // single register can pass the dominance gate.
    let ambiguous_body: Vec<u8> = vec![
        0x49, 0x8B, 0x06, // MOV rax, [r14]
        0x49, 0x89, 0x06, // MOV [r14], rax
        0x49, 0x8B, 0x07, // MOV rax, [r15]
        0x49, 0x89, 0x07, // MOV [r15], rax
    ];
    let handlers: Vec<Vec<u8>> = (0..5).map(|_| ambiguous_body.clone()).collect();
    let roles = analyse_handlers(&handlers, Bitness::X64);
    assert_eq!(roles.vsp, None, "50/50 tie must fall below the >60% dominance gate");
}

#[test]
fn vip_rejected_when_inc_and_dec_balance_out() {
    // r15 gets 5x ADD and 5x SUB — neither monotonic bump nor sink.
    let body: Vec<u8> = vec![
        0x49, 0x83, 0xC7, 0x04, // ADD r15, 4
        0x49, 0x83, 0xEF, 0x04, // SUB r15, 4
    ];
    let handlers: Vec<Vec<u8>> = (0..5).map(|_| body.clone()).collect();
    let roles = analyse_handlers(&handlers, Bitness::X64);
    assert_eq!(roles.vip, None);
}

#[test]
fn vsp_below_min_count_yields_none() {
    // Only 3 indirect touches of r14 total; threshold is 4.
    let short_body: Vec<u8> = vec![0x49, 0x8B, 0x06];
    let handlers: Vec<Vec<u8>> = (0..3).map(|_| short_body.clone()).collect();
    let roles = analyse_handlers(&handlers, Bitness::X64);
    assert_eq!(roles.vsp, None);
}

#[test]
fn vkey_below_min_count_yields_none() {
    // Only 1 XOR-imm — threshold is 2.
    let handlers = vec![vec![0x48, 0x81, 0xF3, 0x00, 0x00, 0x00, 0x00]];
    let roles = analyse_handlers(&handlers, Bitness::X64);
    assert_eq!(roles.vkey, None);
}

// ---------------------------------------------------------------------
// x86 (no REX) — same shapes with 8-register set
// ---------------------------------------------------------------------

#[test]
fn x86_vsp_detected_on_ebx_without_rex() {
    // MOV eax, [ebx]; MOV [ebx], eax
    let body: Vec<u8> = vec![0x8B, 0x03, 0x89, 0x03];
    let handlers: Vec<Vec<u8>> = (0..5).map(|_| body.clone()).collect();
    let roles = analyse_handlers(&handlers, Bitness::X86);
    assert_eq!(roles.vsp, Some(Register::Rbx));
}

#[test]
fn x86_vip_detected_on_esi_without_rex() {
    // ADD esi, 4; MOV eax, [esi]
    // ADD /0 mod=11 rm=6 => ModRM 0xC6.
    let body: Vec<u8> = vec![0x83, 0xC6, 0x04, 0x8B, 0x06];
    let handlers: Vec<Vec<u8>> = (0..5).map(|_| body.clone()).collect();
    let roles = analyse_handlers(&handlers, Bitness::X86);
    assert_eq!(roles.vip, Some(Register::Rsi));
}

#[test]
fn x86_does_not_treat_0x48_as_rex_prefix() {
    // On x86, 0x48 alone is `DEC EAX`, not a REX prefix — a byte
    // sequence that would decode as `REX.W MOV [rax],[rax]` on x64
    // must NOT credit any 64-bit register on x86.
    let body: Vec<u8> = vec![0x48, 0x8B, 0x00]; // DEC EAX; MOV EAX,[EAX]
    let handlers: Vec<Vec<u8>> = (0..5).map(|_| body.clone()).collect();
    let roles = analyse_handlers(&handlers, Bitness::X86);
    // The MOV [rax] portion credits Rax as indirect_load base; no
    // R8..R15 counters should have been touched (they can't be on x86).
    // This is asserted indirectly: vsp resolves to Rax rather than any
    // extended register.
    assert!(matches!(roles.vsp, None | Some(Register::Rax)));
}

// ---------------------------------------------------------------------
// Register enum & serde
// ---------------------------------------------------------------------

#[test]
fn register_from_index_covers_r0_through_r15() {
    for i in 0..=15usize {
        assert!(Register::from_index(i).is_some(), "index {} must map", i);
    }
    assert!(Register::from_index(16).is_none());
}

#[test]
fn register_roles_default_is_all_none() {
    let r = RegisterRoles::default();
    assert!(r.vsp.is_none() && r.vip.is_none() && r.vkey.is_none());
    assert_eq!(r.handlers_seen, 0);
    assert_eq!(r.vsp_consistency, 0.0);
    assert_eq!(r.vip_consistency, 0.0);
    assert_eq!(r.vkey_consistency, 0.0);
}

#[test]
fn register_roles_round_trips_json() {
    let r = RegisterRoles {
        vsp: Some(Register::R14),
        vip: Some(Register::R15),
        vkey: Some(Register::Rbx),
        handlers_seen: 42,
        vsp_consistency: 1.0,
        vip_consistency: 0.85,
        vkey_consistency: 0.7,
    };
    let json = serde_json::to_string(&r).expect("serialize");
    let back: RegisterRoles = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------
// Cross-handler consistency gate (Commit Q — Part A)
// ---------------------------------------------------------------------

/// Fabricated corpus: two thirds of handlers use r14 as VSP, one third
/// uses r8. Aggregate VSP argmax picks r14 (2*count > 1*count) but
/// per-handler agreement is only 2/3 ≈ 0.67 — comfortably above the
/// 0.6 gate, so the aggregate winner survives. This nails down the
/// gate's "just above threshold" behaviour.
#[test]
fn vsp_consistency_around_two_thirds_keeps_aggregate_winner() {
    let r14_body = vsp_r14_body();
    let r8_body: Vec<u8> = vec![
        0x49, 0x8B, 0x00, // MOV rax, [r8]
        0x49, 0x89, 0x00, // MOV [r8], rax
    ];
    let mut handlers: Vec<Vec<u8>> = Vec::new();
    handlers.extend((0..6).map(|_| r14_body.clone()));
    handlers.extend((0..3).map(|_| r8_body.clone()));
    let roles = analyse_handlers(&handlers, Bitness::X64);
    assert_eq!(roles.vsp, Some(Register::R14));
    assert!(
        roles.vsp_consistency > 0.6 && roles.vsp_consistency < 0.75,
        "vsp_consistency={} expected in (0.6, 0.75)",
        roles.vsp_consistency
    );
}

/// Fabricated corpus: three "large" handlers each carry many r14
/// indirect accesses (10 counts apiece); five "small" handlers each
/// carry only two r8 indirect accesses. Aggregate argmax picks r14
/// comfortably (30 counts vs 10, clearing the 60% dominance ratio),
/// BUT per-handler agreement is only 3/8 = 0.375 — below the 0.6
/// gate — so the role must revert to `None`. This is the bias the
/// consistency gate exists to catch: a handful of large handlers
/// swamping many small ones with the wrong convention.
#[test]
fn vsp_reverts_to_none_when_large_handlers_bias_aggregate() {
    // 5x MOV/MOV pairs on r14 -> 10 indirect touches per handler.
    let large_r14_body: Vec<u8> = std::iter::repeat_n(vsp_r14_body(), 5).flatten().collect();
    // Single MOV/MOV pair on r8 -> 2 indirect touches per handler.
    let small_r8_body: Vec<u8> = vec![
        0x49, 0x8B, 0x00, // MOV rax, [r8]
        0x49, 0x89, 0x00, // MOV [r8], rax
    ];
    let mut handlers: Vec<Vec<u8>> = Vec::new();
    handlers.extend((0..3).map(|_| large_r14_body.clone()));
    handlers.extend((0..5).map(|_| small_r8_body.clone()));
    let roles = analyse_handlers(&handlers, Bitness::X64);
    assert_eq!(
        roles.vsp, None,
        "aggregate winner r14 (30 vs 10 counts) must be dropped because \
         per-handler consistency is 3/8 = 0.375"
    );
    assert!(
        (roles.vsp_consistency - 3.0 / 8.0).abs() < 1e-9,
        "vsp_consistency={} expected 0.375",
        roles.vsp_consistency
    );
}

/// VIP consistency: two large handlers dominated by r15 (5 inc counts
/// each) against five small handlers each incrementing r13 once.
/// Aggregate `inc` totals: r15=10, r13=5 → r15 wins the argmax +
/// dominance gate. Per-handler agreement: 2/7 ≈ 0.286 — below the
/// 0.6 gate — so the role reverts to `None`.
#[test]
fn vip_reverts_to_none_when_large_handlers_bias_aggregate() {
    // 5x (ADD r15,4; MOV rax,[r15]) — one inc + one indirect_load per rep.
    let large_r15_body: Vec<u8> = std::iter::repeat_n(vip_r15_body(), 5).flatten().collect();
    // ADD r13,4 = 49 83 C5 04. r13 in indirect memory form requires
    // SIB/disp8, so we skip that here — this handler only touches
    // `inc[r13]`, which is enough to make r13 dominant in it.
    let small_r13_body: Vec<u8> = vec![0x49, 0x83, 0xC5, 0x04];
    let mut handlers: Vec<Vec<u8>> = Vec::new();
    handlers.extend((0..2).map(|_| large_r15_body.clone()));
    handlers.extend((0..5).map(|_| small_r13_body.clone()));
    let roles = analyse_handlers(&handlers, Bitness::X64);
    assert_eq!(
        roles.vip, None,
        "aggregate winner r15 (10 vs 5 inc counts) must be dropped because \
         per-handler consistency is 2/7 ≈ 0.286"
    );
    assert!(
        (roles.vip_consistency - 2.0 / 7.0).abs() < 1e-9,
        "vip_consistency={} expected ~0.286",
        roles.vip_consistency
    );
}
