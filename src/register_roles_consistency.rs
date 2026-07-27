//! Cross-handler consistency gate for [`super::analyse_handlers`].
//!
//! Split out of `register_roles.rs` to keep both files under the
//! crate's 500-line ceiling (see `CLAUDE.md`). The submodule is
//! declared inside `register_roles` via `#[path]`, so it can reach
//! the parent's private `Counters` / `walk_handler` items directly.
//!
//! # What this layer adds on top of the aggregate voter
//!
//! `analyse_handlers` used to pick the argmax register across the
//! whole handler-body corpus and stop. That silently accepted an
//! outcome dominated by a few very large handlers even when the
//! *typical* handler disagreed — a shape a real VMP sample never
//! shows because the register-role convention is baked in at
//! protection time.
//!
//! The consistency gate re-derives dominance PER handler with the
//! same 60%-of-runner-up rule, counts how many agree with the
//! aggregate winner, and either confirms the winner (>=60% agree) or
//! reverts the role to `None` (below that). The fraction is exposed
//! on [`super::RegisterRoles`] so downstream consumers can decide how
//! much to trust the vote.

use super::{walk_handler, Counters, Register};
use crate::Bitness;

/// Per-register counts extracted from a single handler body.
///
/// Public because the consistency check accepts a score closure keyed
/// on it — each role's closure picks the counters that define its
/// shape (`indirect_load + indirect_store` for VSP, `inc` for VIP,
/// `xor_imm` for VKEY).
#[derive(Default, Debug, Clone, Copy)]
#[allow(missing_docs)]
pub struct HandlerCounts {
    pub indirect_load: u32,
    pub indirect_store: u32,
    pub disp_load: u32,
    pub disp_store: u32,
    pub inc: u32,
    pub dec: u32,
    pub xor_imm: u32,
}

/// Minimum fraction of handlers whose per-handler dominant register
/// must agree with the aggregate winner. Below this the aggregate is
/// treated as noise and the corresponding [`super::RegisterRoles`]
/// field reverts to `None`.
///
/// Real VMP-protected binaries bake the register-role convention in
/// at protection time, so a genuine sample sees ~1.0. A drift toward
/// 0.5 signals either a non-VMP corpus or a decoder / classifier bug.
pub(super) const CONSISTENCY_THRESHOLD: f64 = 0.6;

/// Score closure for the VSP role: any indirect memory access — load
/// or store — through the register acting as a pointer.
pub(super) fn vsp_score(c: &HandlerCounts) -> u64 {
    u64::from(c.indirect_load) + u64::from(c.indirect_store)
}

/// Score closure for the VIP role: monotonic bump via `add r, imm`.
/// Per-handler dominance intentionally does NOT re-apply the
/// aggregate voter's "must not be an indirect_store base" filter —
/// that filter is population-level noise suppression, not a
/// per-handler shape.
pub(super) fn vip_score(c: &HandlerCounts) -> u64 {
    u64::from(c.inc)
}

/// Score closure for the VKEY role: `xor r, imm` reg-reg-form target.
pub(super) fn vkey_score(c: &HandlerCounts) -> u64 {
    u64::from(c.xor_imm)
}

/// Per-handler dominant register under `score`.
///
/// Returns the register whose score exceeds every runner-up by more
/// than the 60% dominance ratio used by [`super::vote_vsp`] et al.
/// `None` when the whole handler produced no signal, or when no
/// register clears dominance. `handler` is a single body, not the
/// aggregated population.
pub(super) fn per_handler_dominant_reg(
    handler: &[u8],
    bitness: Bitness,
    score: &dyn Fn(&HandlerCounts) -> u64,
) -> Option<Register> {
    let mut counters = Counters::default();
    walk_handler(handler, bitness, &mut counters);
    let scores: [u64; 16] = std::array::from_fn(|r| score(&counters_for_reg(&counters, r)));
    let (idx, top) = argmax_u64(&scores)?;
    let second = second_max_u64(&scores, idx);
    // Same "> 60% dominance" arithmetic as [`super::vote_vsp`]. u128
    // widening keeps the check overflow-safe even if a future counter
    // type stretches to u64::MAX; the aggregate voter uses u32 counts
    // and can stay on u64 arithmetic.
    if u128::from(top) * 2 <= u128::from(second) * 3 {
        return None;
    }
    Register::from_index(idx)
}

/// Fraction of handlers whose per-handler dominant register equals
/// `winner`. Also returns every disagreeing register seen, so the
/// caller can surface the top runner-ups in the warning log line.
///
/// Denominator is the count of handlers that produced a dominant
/// register FOR THIS ROLE — silent no-signal handlers (which the T
/// audit flagged) are excluded from BOTH sides of the ratio. Rationale:
/// a role like VKEY only fires on handlers with an XOR-imm pattern
/// (~15-25% of typical handlers), and lumping every store-only or
/// arithmetic-only handler into the "disagreement" bucket sinks the
/// ratio well below 60% even when every VOTING handler agrees on the
/// same register. The pre-T formula was `matches / handlers.len()`
/// which caused synthetic VKEY (5/30 voting) to score 16.7% and get
/// dropped.
pub(super) fn handler_agreement(
    handlers: &[Vec<u8>],
    bitness: Bitness,
    winner: Option<Register>,
    score: &dyn Fn(&HandlerCounts) -> u64,
) -> (f64, Vec<Register>) {
    let Some(winner) = winner else {
        return (0.0, Vec::new());
    };
    if handlers.is_empty() {
        return (0.0, Vec::new());
    }
    let mut matches = 0usize;
    let mut voting = 0usize;
    let mut runners = Vec::new();
    for body in handlers {
        match per_handler_dominant_reg(body, bitness, score) {
            Some(reg) if reg == winner => {
                matches += 1;
                voting += 1;
            }
            Some(reg) => {
                runners.push(reg);
                voting += 1;
            }
            None => {}
        }
    }
    if voting == 0 {
        return (0.0, runners);
    }
    (matches as f64 / voting as f64, runners)
}

/// Enforce [`CONSISTENCY_THRESHOLD`] on the aggregate winner. When
/// consistency is below the bar the role reverts to `None` and a
/// warning names the top disagreeing registers so the analyst can
/// spot corpus drift.
pub(super) fn apply_consistency_gate(
    role: &str,
    winner: Option<Register>,
    consistency: f64,
    runners: &[Register],
) -> Option<Register> {
    let winner = winner?;
    if consistency >= CONSISTENCY_THRESHOLD {
        return Some(winner);
    }
    let mut runner_summary: Vec<(&'static str, usize)> = Vec::new();
    for reg in runners {
        if let Some(entry) = runner_summary.iter_mut().find(|(name, _)| *name == reg.as_str()) {
            entry.1 += 1;
        } else {
            runner_summary.push((reg.as_str(), 1));
        }
    }
    runner_summary.sort_by_key(|entry| std::cmp::Reverse(entry.1));
    let joined: Vec<String> = runner_summary
        .into_iter()
        .map(|(name, n)| format!("{}x{}", name, n))
        .collect();
    let runners_str = if joined.is_empty() {
        "none".to_string()
    } else {
        joined.join(", ")
    };
    log::warn!(
        "{} aggregate winner {} rejected: cross-handler consistency {:.2} below threshold {:.2}; \
         disagreeing handlers dominated by [{}]",
        role,
        winner.as_str(),
        consistency,
        CONSISTENCY_THRESHOLD,
        runners_str,
    );
    None
}

/// Extract the per-register slice for `reg_index` as a
/// [`HandlerCounts`] snapshot. Cheap: seven u32 copies.
fn counters_for_reg(c: &Counters, reg_index: usize) -> HandlerCounts {
    HandlerCounts {
        indirect_load: c.indirect_load[reg_index],
        indirect_store: c.indirect_store[reg_index],
        disp_load: c.disp_load[reg_index],
        disp_store: c.disp_store[reg_index],
        inc: c.inc[reg_index],
        dec: c.dec[reg_index],
        xor_imm: c.xor_imm[reg_index],
    }
}

/// u64 variant of [`super::argmax`] used by the per-handler
/// consistency helper. Same zero-skip and lowest-index tiebreak
/// semantics.
fn argmax_u64(arr: &[u64; 16]) -> Option<(usize, u64)> {
    let mut best: Option<(usize, u64)> = None;
    for (i, &v) in arr.iter().enumerate() {
        if v == 0 {
            continue;
        }
        match best {
            Some((_, b)) if v <= b => {}
            _ => best = Some((i, v)),
        }
    }
    best
}

/// u64 variant of [`super::second_max`].
fn second_max_u64(arr: &[u64; 16], skip: usize) -> u64 {
    arr.iter()
        .enumerate()
        .filter_map(|(i, &v)| if i == skip { None } else { Some(v) })
        .max()
        .unwrap_or(0)
}
