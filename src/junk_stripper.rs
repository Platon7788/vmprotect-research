//! Junk-code stripper — a peephole pre-pass over handler bodies.
//!
//! VMP 3.x wraps every mutator emission in a "0-3 junk instructions"
//! envelope: single-instruction no-ops (mov reg,reg / lea reg,[reg] /
//! add reg,0 / and reg,-1 / stray segment prefixes) and adjacent
//! push/pop register-juggling. These instructions have no observable
//! effect on the VM state that [`crate::handler_semantic::SemanticMatcher`]
//! cares about, but their presence between the load / adjust / store
//! steps that make up a real handler pattern degrades any matcher that
//! walks instructions sequentially rather than "presence anywhere".
//!
//! Running this stripper BEFORE the semantic matcher restores the
//! "signature reliability" the audit report calls out (§5, §6.2 of
//! `RESEARCH_GAPS.md`) and prepares the ground for future sequential
//! matchers.
//!
//! Sources of the pattern catalogue used here: RESEARCH_GAPS.md §5,
//! MITRE T1027.016, mrphrazer's obfuscation_detection primer, and
//! DiE/PEiD community writeups. No source was copied from the GPL-3
//! `vmpattack` / `NoVmp` reference implementations.
//!
//! Design constraints:
//!
//! - Conservative: when a junk-shaped span cannot be proven safe (e.g.
//!   a push/pop pair with an intervening instruction whose register use
//!   we can't cheaply prove absent), leave it alone.
//! - Bitness-aware: on x86, 0x40..0x4F are `INC/DEC r32`, NOT REX
//!   prefixes; on x64 they are REX and must be transparent to same-reg
//!   checks (see [`same_register`]).
//! - Length-decoded fallback: when a non-junk instruction is skipped
//!   we advance by its actual length so later junk matches don't fire
//!   inside a real instruction's immediate/displacement bytes (a
//!   spurious `LEA [reg]` match in the middle of a `MOV RAX, imm64`
//!   would silently corrupt the handler body).

use crate::Bitness;

// Instruction-length decoder lives in a sibling file so this impl
// file stays under the project's 500-line ceiling. The submodule is
// private (pub(super) at its edges) — it exists only to serve this
// stripper.
#[path = "junk_stripper_length.rs"]
mod length;
use length::{instruction_length, parse_modrm_length, read_rex};

/// Strip junk instructions from a handler body, returning the reduced byte sequence.
///
/// Two-phase peephole:
///
/// 1. Remove single-instruction junk (Groups A/C/D — same-register ops,
///    trivially foldable arithmetic, stray segment prefixes, NOPs).
/// 2. On the reduced body, remove `push reg` / `pop reg` pairs that are
///    now adjacent (Group B). The two-phase ordering realises the
///    "no intervening use" invariant implicitly: any real intervening
///    instruction is preserved by phase 1, so the pop never becomes
///    adjacent to its push and the pair is left alone.
pub fn strip_junk(bytecode: &[u8], bitness: Bitness) -> Vec<u8> {
    let phase1 = strip_single_instruction_junk(bytecode, bitness);
    strip_push_pop_pairs(&phase1, bitness)
}

// ---------------------------------------------------------------------
// Phase 1 — single-instruction junk.
// ---------------------------------------------------------------------

fn strip_single_instruction_junk(bytecode: &[u8], bitness: Bitness) -> Vec<u8> {
    let mut result = Vec::with_capacity(bytecode.len());
    let mut i = 0;
    while i < bytecode.len() {
        if let Some(len) = try_match_junk(bytecode, i, bitness) {
            i += len;
            continue;
        }
        if let Some(len) = instruction_length(bytecode, i, bitness) {
            // The length decoder can return 0 only for a defensive
            // corner (opcode-less prefix run at EOF); clamp to 1 so we
            // always make forward progress.
            let step = len.max(1);
            let end = (i + step).min(bytecode.len());
            result.extend_from_slice(&bytecode[i..end]);
            i = end;
        } else {
            // Unknown opcode: byte-by-byte fallback. Junk patterns are
            // specific enough that spurious mid-instruction matches are
            // rare, but the length-decoded path above avoids them for
            // the common instruction set.
            result.push(bytecode[i]);
            i += 1;
        }
    }
    result
}

/// Try to match a single junk instruction at position `i`. Returns the
/// instruction length (INCLUDING any prefix bytes) on match, else None.
fn try_match_junk(bytecode: &[u8], i: usize, bitness: Bitness) -> Option<usize> {
    if i >= bytecode.len() {
        return None;
    }

    // Group D: standalone segment prefixes not followed by a memory op.
    // A segment prefix followed by a ModR/M with mem operand is real;
    // followed by a non-memory instruction it's junk. We handle this
    // conservatively by only stripping a segment prefix when the very
    // next byte is itself a prefix or a single-byte no-op / same-reg
    // op — anything with a ModR/M we leave alone.
    if let Some(len) = try_match_stray_segment_prefix(bytecode, i, bitness) {
        return Some(len);
    }

    // Consume an optional REX prefix (x64 only).
    let (rex, p) = read_rex(bytecode, i, bitness);
    let op = *bytecode.get(p)?;

    // Group A: single-byte NOP (0x90). On x86 without REX; on x64
    // technically `xchg rax, rax`, which is also a no-op.
    if op == 0x90 && rex.is_none() {
        return Some(1);
    }

    // Group A: multi-byte NOP (0x0F 0x1F /0 …).
    if op == 0x0F && bytecode.get(p + 1).copied() == Some(0x1F) {
        // ModR/M + optional SIB + optional displacement.
        let modrm_len = parse_modrm_length(bytecode, p + 2)?;
        return Some(p - i + 2 + modrm_len);
    }

    // Group A: same-register mov / xchg / lea / or / and.
    if let Some(len) = try_match_same_reg_op(bytecode, i, p, rex, op) {
        return Some(len);
    }

    // Group C: trivially foldable `op reg, imm8` with a nil immediate.
    if let Some(len) = try_match_trivial_group1_imm8(bytecode, i, p, op) {
        return Some(len);
    }

    None
}

// ---------------------------------------------------------------------
// Group A helpers.
// ---------------------------------------------------------------------

/// Same-register two-operand ops: `mov r,r` (0x89 / 0x8B), `xchg r,r`
/// (0x87), `or r,r` (0x09 / 0x0B), `and r,r` (0x21 / 0x23),
/// `lea r,[r]` / `lea r,[r+0]` / `lea r,[r+0x00000000]` (0x8D).
///
/// Returns Some(total_length_including_rex) when the encoding is a
/// no-op — reg-field register equals rm-field register (with REX bits
/// consulted to disambiguate r8..r15 from rax..rdi).
fn try_match_same_reg_op(bytecode: &[u8], i: usize, p: usize, rex: Option<u8>, op: u8) -> Option<usize> {
    match op {
        // MOV r/m, r (0x89) and MOV r, r/m (0x8B) — mod=11 with reg==rm.
        // XCHG r/m, r (0x87) — mod=11 with reg==rm. Note: `xchg eax, r32`
        // has its own opcodes 0x90..0x97 and is not covered here.
        // OR / AND with same reg — flag-touch only but still emitted as junk.
        0x89 | 0x8B | 0x87 | 0x09 | 0x0B | 0x21 | 0x23 => {
            let modrm = *bytecode.get(p + 1)?;
            if (modrm & 0xC0) == 0xC0 && same_register(modrm, rex) {
                return Some(p - i + 2);
            }
            None
        }
        // LEA r, [mem] — three no-op mem forms.
        0x8D => {
            let modrm = *bytecode.get(p + 1)?;
            let mode = modrm & 0xC0;
            let rm = modrm & 0x07;
            // Reject SIB (rm=4) and RIP-relative / disp32-abs (rm=5).
            // Neither is expressible as the "[same reg]" no-op we want.
            if rm == 4 || rm == 5 {
                return None;
            }
            if !same_register(modrm, rex) {
                return None;
            }
            match mode {
                // lea r, [r]
                0x00 => Some(p - i + 2),
                // lea r, [r+disp8] — no-op only if disp8 == 0
                0x40 => {
                    let disp = *bytecode.get(p + 2)?;
                    if disp == 0 {
                        Some(p - i + 3)
                    } else {
                        None
                    }
                }
                // lea r, [r+disp32] — no-op only if disp32 == 0
                0x80 => {
                    let end = p + 2 + 4;
                    if bytecode.len() < end {
                        return None;
                    }
                    let disp = u32::from_le_bytes(bytecode[p + 2..end].try_into().ok()?);
                    if disp == 0 {
                        Some(p - i + 6)
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// True when a ModR/M byte's `reg` field and `rm` field reference the
/// same physical register. Under REX both fields are extended by one
/// bit each (`REX.R` → reg high bit, `REX.B` → rm high bit); "same"
/// therefore requires those two REX bits to agree as well.
fn same_register(modrm: u8, rex: Option<u8>) -> bool {
    let reg = (modrm >> 3) & 0x07;
    let rm = modrm & 0x07;
    if reg != rm {
        return false;
    }
    match rex {
        Some(r) => ((r >> 2) & 1) == (r & 1),
        None => true,
    }
}

// ---------------------------------------------------------------------
// Group C — trivially foldable `op reg, imm8` with nil immediate.
// ---------------------------------------------------------------------

/// `0x83 /n imm8` group. The `/n` field is bits 3..5 of the ModR/M
/// byte. We accept:
///
///   /0 (ADD) imm8 == 0
///   /1 (OR)  imm8 == 0
///   /4 (AND) imm8 == 0xFF (sign-extends to -1)
///   /5 (SUB) imm8 == 0
///
/// with the ModR/M mod field == 11 (reg operand). Memory-operand
/// forms are kept because they still touch memory.
fn try_match_trivial_group1_imm8(bytecode: &[u8], i: usize, p: usize, op: u8) -> Option<usize> {
    if op != 0x83 {
        return None;
    }
    let modrm = *bytecode.get(p + 1)?;
    if (modrm & 0xC0) != 0xC0 {
        return None;
    }
    let imm = *bytecode.get(p + 2)?;
    let subop = (modrm >> 3) & 0x07;
    let is_junk = match subop {
        0 => imm == 0,    // ADD reg, 0
        1 => imm == 0,    // OR reg, 0
        4 => imm == 0xFF, // AND reg, -1 (sign-extended imm8)
        5 => imm == 0,    // SUB reg, 0
        _ => return None,
    };
    if is_junk {
        Some(p - i + 3)
    } else {
        None
    }
}

// ---------------------------------------------------------------------
// Group D — stray segment prefixes.
// ---------------------------------------------------------------------

fn is_segment_prefix(b: u8) -> bool {
    matches!(b, 0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65)
}

/// Segment prefixes are junk only when they don't front a memory op.
/// We keep the classifier conservative: strip a segment prefix that is
/// immediately followed by another prefix or by an instruction with
/// mod=11 (register operand) at the ModR/M byte. Anything else we
/// leave alone so we never accidentally cut FS:/GS: memory accesses,
/// which VMP does use to fetch TEB fields.
fn try_match_stray_segment_prefix(bytecode: &[u8], i: usize, bitness: Bitness) -> Option<usize> {
    let b = *bytecode.get(i)?;
    if !is_segment_prefix(b) {
        return None;
    }
    // Peek past additional prefixes (REX, other segments) — if we hit
    // an opcode whose ModR/M is mod=11 (register-register), strip only
    // the leading segment prefix. Otherwise (mem op or unknown) keep.
    let (_rex, p) = read_rex(bytecode, i + 1, bitness);
    let op = *bytecode.get(p)?;

    // A trailing single-byte instruction (NOP / PUSH r / POP r / RET /
    // XCHG EAX, r) has no memory operand — the prefix is stray junk.
    if matches!(op, 0x90 | 0x50..=0x5F | 0xC3) {
        return Some(1);
    }
    // Two-operand ops with ModR/M — strip only when mod=11.
    if matches!(
        op,
        0x89 | 0x8B
            | 0x87
            | 0x8D
            | 0x01
            | 0x03
            | 0x29
            | 0x2B
            | 0x31
            | 0x33
            | 0x09
            | 0x0B
            | 0x21
            | 0x23
            | 0x83
            | 0x81
            | 0x8F
            | 0xC7
            | 0xF7
            | 0xFF
            | 0x69
            | 0x6B
    ) {
        let modrm = *bytecode.get(p + 1)?;
        if (modrm & 0xC0) == 0xC0 {
            return Some(1);
        }
    }
    None
}

// ---------------------------------------------------------------------
// Phase 2 — push/pop register-juggling pairs.
// ---------------------------------------------------------------------

fn strip_push_pop_pairs(bytecode: &[u8], bitness: Bitness) -> Vec<u8> {
    // Fixed-point iteration so nested `push A; push A; pop A; pop A`
    // reduces fully — the inner pair goes on pass one, the outer pair
    // (now adjacent) on pass two.
    let mut current = bytecode.to_vec();
    loop {
        let next = strip_push_pop_pairs_once(&current, bitness);
        if next.len() == current.len() {
            return next;
        }
        current = next;
    }
}

fn strip_push_pop_pairs_once(bytecode: &[u8], bitness: Bitness) -> Vec<u8> {
    let mut result = Vec::with_capacity(bytecode.len());
    let mut i = 0;
    while i < bytecode.len() {
        if let Some(len) = try_match_adjacent_push_pop(bytecode, i, bitness) {
            i += len;
            continue;
        }
        result.push(bytecode[i]);
        i += 1;
    }
    result
}

/// Match `push reg` immediately followed by `pop reg` of the same
/// register. Handles the x64 REX.B extension: `41 50 41 58` is
/// `push r8; pop r8`.
fn try_match_adjacent_push_pop(bytecode: &[u8], i: usize, bitness: Bitness) -> Option<usize> {
    let (push_len, push_reg) = parse_push_reg(bytecode, i, bitness)?;
    let (pop_len, pop_reg) = parse_pop_reg(bytecode, i + push_len, bitness)?;
    if push_reg == pop_reg {
        Some(push_len + pop_len)
    } else {
        None
    }
}

fn parse_push_reg(bytecode: &[u8], i: usize, bitness: Bitness) -> Option<(usize, u8)> {
    let (rex, p) = read_rex(bytecode, i, bitness);
    let op = *bytecode.get(p)?;
    if !(0x50..=0x57).contains(&op) {
        return None;
    }
    let reg = (op - 0x50) | (rex.map(|r| (r & 0x01) << 3).unwrap_or(0));
    Some((p - i + 1, reg))
}

fn parse_pop_reg(bytecode: &[u8], i: usize, bitness: Bitness) -> Option<(usize, u8)> {
    let (rex, p) = read_rex(bytecode, i, bitness);
    let op = *bytecode.get(p)?;
    if !(0x58..=0x5F).contains(&op) {
        return None;
    }
    let reg = (op - 0x58) | (rex.map(|r| (r & 0x01) << 3).unwrap_or(0));
    Some((p - i + 1, reg))
}

// ---------------------------------------------------------------------
// Length decoding lives in `junk_stripper_length.rs`
// (see `mod length` above). Kept out of this file so the impl stays
// under the project's 500-line ceiling.
// ---------------------------------------------------------------------

#[cfg(test)]
#[path = "junk_stripper_tests.rs"]
mod tests;
