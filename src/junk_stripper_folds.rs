//! Groups E, F, G of the junk stripper.
//!
//! Split out of `junk_stripper.rs` via `#[path]` include so the impl
//! file stays under the project's 500-line ceiling (see `CLAUDE.md`),
//! same convention as `junk_stripper_length.rs` and
//! `junk_stripper_effects.rs`.
//!
//! - **Group E** — constant-folding pairs (`add r,K` / `sub r,K`,
//!   double `xor r,K`, `inc r` / `dec r`, `neg`/`neg`, `not`/`not`,
//!   plus `add r,K1` / `add r,K2` where K1+K2 == 0). Anchor and cancel
//!   must live within a 32-byte window, with no branch, memory
//!   touch, or intermediate write to the target register between them.
//! - **Group F** — dead-store elimination: `mov r, X` followed by any
//!   next write to `r` (with no intermediate read of `r`).
//! - **Group G** — one backward-liveness pass. A `mov`/`lea` whose only
//!   output is a register that is never read again gets removed.
//!
//! All three passes reuse the shared instruction-effect decoder in
//! `super::effects`.
//!
//! References: Muchnick "Advanced Compiler Design & Implementation"
//! ch. 12 (peephole), Cooper & Torczon "Engineering a Compiler" §10.6
//! (dead-code elimination via liveness). No code copied from any
//! GPL-licensed reference; this is a bespoke byte-level implementation
//! sized for VMP handler bodies.

use super::effects::{decode, Insn, Kind, R_NONE};
use crate::Bitness;

/// Distance limit (in bytes) between the two halves of a Group E pair.
/// Chosen empirically from the VMP-3 mutation envelopes we've seen:
/// three or four "shape" instructions between a real operation and its
/// junk inverse are common; the outer envelope is bounded by the
/// dispatcher's tail-call which lives ≤ 32 bytes away. Larger windows
/// mostly cost CPU without adding hits, and would start to overlap
/// unrelated pairs.
const PAIR_WINDOW_BYTES: usize = 32;

// ---------------------------------------------------------------------
// Public entry points — each pass takes a byte slice and returns the
// reduced byte sequence, preserving every non-classified instruction
// verbatim.
// ---------------------------------------------------------------------

/// Group E — cancel foldable `op K` pairs.
pub(super) fn strip_constant_folds(bytecode: &[u8], bitness: Bitness) -> Vec<u8> {
    let insns = decode_all(bytecode, bitness);
    if insns.is_empty() {
        return bytecode.to_vec();
    }
    let mut removed = vec![false; insns.len()];
    for i in 0..insns.len() {
        if removed[i] {
            continue;
        }
        let anchor = &insns[i];
        let Some(target_reg) = anchor_target_reg(&anchor.info) else {
            continue;
        };
        let mut j = i + 1;
        while j < insns.len() {
            if removed[j] {
                j += 1;
                continue;
            }
            let cand = &insns[j];
            let distance = cand.offset - anchor.offset;
            if distance > PAIR_WINDOW_BYTES {
                break;
            }
            if cand.info.is_control_flow || cand.info.is_opaque {
                break;
            }
            if cand.info.memory_load || cand.info.memory_store {
                break;
            }
            if cancels(&anchor.info.kind, &cand.info.kind) {
                removed[i] = true;
                removed[j] = true;
                break;
            }
            // Any intermediate write to the target register defeats
            // the fold — the second operation would no longer see the
            // same value the anchor produced.
            if (cand.info.writes & (1u16 << target_reg)) != 0 {
                break;
            }
            j += 1;
        }
    }
    emit(bytecode, &insns, &removed)
}

/// Group F — dead-store elimination.
pub(super) fn strip_dead_stores(bytecode: &[u8], bitness: Bitness) -> Vec<u8> {
    let insns = decode_all(bytecode, bitness);
    if insns.is_empty() {
        return bytecode.to_vec();
    }
    let mut removed = vec![false; insns.len()];
    for i in 0..insns.len() {
        if removed[i] {
            continue;
        }
        let anchor = &insns[i];
        let Some(target_reg) = deadstore_target_reg(&anchor.info) else {
            continue;
        };
        let bit = 1u16 << target_reg;
        let mut j = i + 1;
        while j < insns.len() {
            if removed[j] {
                j += 1;
                continue;
            }
            let cand = &insns[j];
            if cand.info.is_control_flow || cand.info.is_opaque {
                break;
            }
            // Reading the target reg means the anchor's write is
            // observed downstream — must be preserved.
            if (cand.info.reads & bit) != 0 {
                break;
            }
            if (cand.info.writes & bit) != 0 {
                // Next write to target_reg arrived with no intervening
                // read — anchor is dead.
                removed[i] = true;
                break;
            }
            j += 1;
        }
    }
    emit(bytecode, &insns, &removed)
}

/// Group G — one backward-liveness pass.
///
/// Assumes the tail live-out is "all GPRs" (conservative: a VMP
/// handler tails into an indirect JMP into the dispatcher, which we
/// can't cheaply constrain). Removes only pure register writes with
/// no memory, flag, or control-flow side effects — the same class we
/// were happy to remove in Groups A/E/F.
pub(super) fn strip_dead_regs_backward(bytecode: &[u8], bitness: Bitness) -> Vec<u8> {
    let insns = decode_all(bytecode, bitness);
    if insns.is_empty() {
        return bytecode.to_vec();
    }
    let mut removed = vec![false; insns.len()];
    let mut live_out: u16 = 0xFFFF;
    for j in (0..insns.len()).rev() {
        let insn = &insns[j].info;
        // Spec (Commit P Group G): "Skip if the instruction has a
        // memory-store side effect or a flag-touch side effect that
        // matters." Memory *loads* are explicitly not on that list —
        // Group F already strips dead memory loads (`mov r, [mem]` /
        // `mov r, [mem2]`), and Group G is the mop-up pass, so we
        // mirror F's tolerance here. Faulting-load concerns are a
        // non-issue inside a well-formed VMP handler body.
        let can_remove = !insn.is_opaque
            && !insn.is_control_flow
            && !insn.memory_store
            && !insn.touches_flags
            && insn.writes != R_NONE
            && (insn.writes & live_out) == 0;
        if can_remove {
            removed[j] = true;
            // Removal doesn't change live-in for the predecessor —
            // a dead write reads no regs the caller will see.
            continue;
        }
        live_out = (live_out & !insn.writes) | insn.reads;
    }
    emit(bytecode, &insns, &removed)
}

// ---------------------------------------------------------------------
// Internal helpers.
// ---------------------------------------------------------------------

struct At {
    offset: usize,
    info: Insn,
}

fn decode_all(bytecode: &[u8], bitness: Bitness) -> Vec<At> {
    let mut v = Vec::new();
    let mut i = 0;
    while i < bytecode.len() {
        match decode(bytecode, i, bitness) {
            Some(info) => {
                let step = info.len.max(1);
                let end = (i + step).min(bytecode.len());
                // The decoder can promise `len` extends past EOF for a
                // truncated final instruction; clamp so we emit exactly
                // the bytes present in the input rather than reading
                // past its end during `emit`.
                let clamped_len = end - i;
                let mut clamped = info;
                clamped.len = clamped_len;
                v.push(At {
                    offset: i,
                    info: clamped,
                });
                i = end;
            }
            None => break,
        }
    }
    v
}

fn emit(bytecode: &[u8], insns: &[At], removed: &[bool]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytecode.len());
    for (idx, at) in insns.iter().enumerate() {
        if !removed[idx] {
            let end = (at.offset + at.info.len).min(bytecode.len());
            out.extend_from_slice(&bytecode[at.offset..end]);
        }
    }
    out
}

/// The register whose value the pair operation reads and writes. `None`
/// for kinds that don't fit Group E's anchor set.
fn anchor_target_reg(insn: &Insn) -> Option<u8> {
    match insn.kind {
        Kind::AddRegImm { reg, .. }
        | Kind::SubRegImm { reg, .. }
        | Kind::XorRegImm { reg, .. }
        | Kind::IncReg(reg)
        | Kind::DecReg(reg)
        | Kind::NegReg(reg)
        | Kind::NotReg(reg) => Some(reg),
        _ => None,
    }
}

/// Group F anchor set — `mov r, X` and `lea r, [x]`. Skips any shape
/// that touches memory, flags, or has an unclear write set.
fn deadstore_target_reg(insn: &Insn) -> Option<u8> {
    if insn.memory_store || insn.touches_flags || insn.is_control_flow || insn.is_opaque {
        return None;
    }
    match insn.kind {
        Kind::MovRegDst(reg) | Kind::LeaRegDst(reg) => Some(reg),
        _ => None,
    }
}

/// True when the two kinds form a canceling pair, per the Group E
/// specification.
fn cancels(a: &Kind, b: &Kind) -> bool {
    match (a, b) {
        // add r, K ; sub r, K
        (Kind::AddRegImm { reg: ra, imm: ia }, Kind::SubRegImm { reg: rb, imm: ib }) if ra == rb => ia == ib,
        // sub r, K ; add r, K
        (Kind::SubRegImm { reg: ra, imm: ia }, Kind::AddRegImm { reg: rb, imm: ib }) if ra == rb => ia == ib,
        // add r, K1 ; add r, K2 where K1 + K2 == 0
        (Kind::AddRegImm { reg: ra, imm: ia }, Kind::AddRegImm { reg: rb, imm: ib }) if ra == rb => {
            ia.wrapping_add(*ib) == 0
        }
        // xor r, K ; xor r, K (double XOR)
        (Kind::XorRegImm { reg: ra, imm: ia }, Kind::XorRegImm { reg: rb, imm: ib }) if ra == rb => ia == ib,
        // inc r ; dec r
        (Kind::IncReg(ra), Kind::DecReg(rb)) => ra == rb,
        (Kind::DecReg(ra), Kind::IncReg(rb)) => ra == rb,
        // neg r ; neg r
        (Kind::NegReg(ra), Kind::NegReg(rb)) => ra == rb,
        // not r ; not r
        (Kind::NotReg(ra), Kind::NotReg(rb)) => ra == rb,
        _ => false,
    }
}
