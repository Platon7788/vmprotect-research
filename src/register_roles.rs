//! Register-role canonicaliser (RESEARCH_GAPS.md §7 item #7).
//!
//! Pattern-heuristic identification of which x86 GPR plays the role of
//! VIP (VM instruction pointer), VSP (VM stack pointer), and VKEY
//! (running crypto state, VMP 3.x+) inside a VMP handler body.
//!
//! Byte-level, no full disassembler: we walk each handler body counting
//! a small set of shapes we can attribute to a specific register, then
//! vote at the register level across all handlers. Behaviour references:
//! NoVmp / vmpattack / cyber.wtf VMProtect writeups — no code copied
//! from any of those GPL sources.
//!
//! Voting is deliberately conservative — thresholds + a
//! dominance-over-runner-up gate — so an ambiguous handler set returns
//! `None` for the affected role rather than a low-confidence guess.
//!
//! # Encoding notes
//!
//! - REX prefix (0x40..=0x4F) is x64-only: on x86 those bytes are
//!   1-byte INC/DEC r32 opcodes, not prefixes. `decode_one` skips REX
//!   only when `bitness == Bitness::X64`.
//! - REX.B (bit 0) extends the r/m field to r8..r15. REX.R (bit 2)
//!   extends the reg field. We only credit the *base* register of a
//!   memory access (the r/m register in mod=00/01/10), which is the
//!   register acting like a pointer — the register we care about for
//!   VIP/VSP.
//! - `0x83 /n imm8` and `0x81 /n imm32` are Group-1 immediate ops with
//!   an opcode extension in the reg field: /0 = ADD, /5 = SUB, /6 =
//!   XOR. We only look at the reg-reg form (mod=11) here since VSP/VIP
//!   bumps and running-key XOR are always encoded that way.

use crate::Bitness;

/// x86 register identifier. r0..r7 on x86; r0..r15 on x64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[allow(missing_docs)]
pub enum Register {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl Register {
    /// Map a 0..=15 index (r/m field with REX.B applied) to a register.
    fn from_index(i: usize) -> Option<Register> {
        Some(match i {
            0 => Register::Rax,
            1 => Register::Rcx,
            2 => Register::Rdx,
            3 => Register::Rbx,
            4 => Register::Rsp,
            5 => Register::Rbp,
            6 => Register::Rsi,
            7 => Register::Rdi,
            8 => Register::R8,
            9 => Register::R9,
            10 => Register::R10,
            11 => Register::R11,
            12 => Register::R12,
            13 => Register::R13,
            14 => Register::R14,
            15 => Register::R15,
            _ => return None,
        })
    }

    /// Short mnemonic, used in the audit-trail log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Register::Rax => "rax",
            Register::Rcx => "rcx",
            Register::Rdx => "rdx",
            Register::Rbx => "rbx",
            Register::Rsp => "rsp",
            Register::Rbp => "rbp",
            Register::Rsi => "rsi",
            Register::Rdi => "rdi",
            Register::R8 => "r8",
            Register::R9 => "r9",
            Register::R10 => "r10",
            Register::R11 => "r11",
            Register::R12 => "r12",
            Register::R13 => "r13",
            Register::R14 => "r14",
            Register::R15 => "r15",
        }
    }
}

/// Which x86 register plays which VMP-VM role.
///
/// A field of `None` means the voter had no confident winner for that
/// role — either not enough signal, or two candidates too close to
/// call. Consumers should treat `None` as "unknown" and not fall back
/// to the runner-up.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RegisterRoles {
    /// Candidate VSP (VM stack pointer) — the register with the highest
    /// count of indirect memory accesses (both loads and stores at
    /// mod=00) across all analysed handler bodies.
    pub vsp: Option<Register>,
    /// Candidate VIP (VM instruction pointer) — the register that's
    /// incremented by small immediate constants (`add r, imm8`) most
    /// frequently, filtered to registers that are rarely used as an
    /// indirect-store base (VIP is loaded from, not stored through).
    pub vip: Option<Register>,
    /// Candidate VKEY (running crypto state, VMP 3.x+) — the register
    /// most frequently used as the target of an XOR-with-immediate.
    /// `None` when the sample shows no XOR-imm signal at all, which
    /// is the expected shape for VMP 1.x (no running-key crypto).
    pub vkey: Option<Register>,
    /// Total number of handler bodies analysed. Low count means low
    /// confidence — consumers should treat sub-16-handler results as
    /// noisy.
    pub handlers_seen: usize,
}

/// Analyse a set of handler bodies and vote on register roles.
///
/// `handlers` is a slice of already-read handler bodies (typically the
/// same up-to-100-byte prefixes fed to
/// [`crate::handler_classifier::HandlerClassifier`]). `bitness` gates
/// the REX-prefix branch — see module docs.
pub fn analyse_handlers(handlers: &[Vec<u8>], bitness: Bitness) -> RegisterRoles {
    let mut counters = Counters::default();
    for body in handlers {
        walk_handler(body, bitness, &mut counters);
    }
    let roles = RegisterRoles {
        vsp: vote_vsp(&counters),
        vip: vote_vip(&counters),
        vkey: vote_vkey(&counters),
        handlers_seen: handlers.len(),
    };
    log_top_candidates(&counters, &roles);
    roles
}

// ---------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------

/// Per-register tallies collected across every analysed handler body.
///
/// Indexed 0..=15 via the r/m field with REX.B applied — see
/// [`Register::from_index`]. On x86 (`Bitness::X86`) only slots 0..=7
/// are ever touched because REX doesn't exist there.
#[derive(Default, Debug)]
struct Counters {
    indirect_load: [u32; 16],
    indirect_store: [u32; 16],
    disp_load: [u32; 16],
    disp_store: [u32; 16],
    inc: [u32; 16],
    dec: [u32; 16],
    xor_imm: [u32; 16],
}

// ---------------------------------------------------------------------
// Byte walker
// ---------------------------------------------------------------------

fn walk_handler(bytes: &[u8], bitness: Bitness, counters: &mut Counters) {
    let mut i = 0usize;
    while i < bytes.len() {
        let advance = decode_one(bytes, i, bitness, counters);
        // Advance-by-at-least-one guards against a decode helper that
        // recognises a REX prefix but returns 0 for the following
        // unknown opcode; without this the loop would spin.
        i = i.saturating_add(advance.max(1));
    }
}

/// Decode a single instruction starting at `pos`. Returns bytes to
/// advance. Unrecognised opcodes return 1 (skip-a-byte fallback).
///
/// Not a full x86 decoder: we only handle the small shape set the
/// voter needs (`MOV r,[r]`, `MOV [r],r`, `MOV r,[r+disp]`, `MOV
/// [r+disp],r`, and Group-1 `ADD/SUB/XOR r, imm`). Everything else
/// falls through the 1-byte fallback — mis-decoded bytes downstream
/// self-correct within a few positions and, since we aggregate across
/// many handlers, isolated noise is tolerable.
fn decode_one(bytes: &[u8], pos: usize, bitness: Bitness, counters: &mut Counters) -> usize {
    let mut p = pos;
    let mut rex_b = false;
    let mut prefix_len = 0usize;

    if bitness == Bitness::X64 {
        if let Some(&b) = bytes.get(p) {
            if (0x40..=0x4F).contains(&b) {
                rex_b = (b & 0x01) != 0;
                p += 1;
                prefix_len = 1;
            }
        }
    }

    let opcode = match bytes.get(p) {
        Some(&b) => b,
        None => return prefix_len.max(1),
    };

    match opcode {
        0x8B => decode_mov_load(bytes, p, prefix_len, rex_b, counters),
        0x89 => decode_mov_store(bytes, p, prefix_len, rex_b, counters),
        0x83 => decode_group1_imm8(bytes, p, prefix_len, rex_b, counters),
        0x81 => decode_group1_imm32(bytes, p, prefix_len, rex_b, counters),
        _ => 1,
    }
}

fn decode_mov_load(bytes: &[u8], p: usize, prefix_len: usize, rex_b: bool, counters: &mut Counters) -> usize {
    let modrm = match bytes.get(p + 1) {
        Some(&b) => b,
        None => return 1,
    };
    let mode = modrm & 0xC0;
    let rm = modrm & 0x07;
    let base_idx = (rm as usize) + if rex_b { 8 } else { 0 };
    match mode {
        0x00 => {
            if rm != 4 && rm != 5 {
                counters.indirect_load[base_idx] += 1;
                prefix_len + 2
            } else if rm == 4 {
                // SIB byte follows — advance past opcode + ModR/M + SIB.
                prefix_len + 3
            } else {
                // rm == 5: RIP-relative on x64 / disp32 on x86.
                prefix_len + 6
            }
        }
        0x40 => {
            let sib = usize::from(rm == 4);
            if rm != 4 {
                counters.disp_load[base_idx] += 1;
            }
            prefix_len + 2 + sib + 1
        }
        0x80 => {
            let sib = usize::from(rm == 4);
            if rm != 4 {
                counters.disp_load[base_idx] += 1;
            }
            prefix_len + 2 + sib + 4
        }
        0xC0 => prefix_len + 2, // reg-reg MOV — not tracked here.
        _ => 1,
    }
}

fn decode_mov_store(bytes: &[u8], p: usize, prefix_len: usize, rex_b: bool, counters: &mut Counters) -> usize {
    let modrm = match bytes.get(p + 1) {
        Some(&b) => b,
        None => return 1,
    };
    let mode = modrm & 0xC0;
    let rm = modrm & 0x07;
    let base_idx = (rm as usize) + if rex_b { 8 } else { 0 };
    match mode {
        0x00 => {
            if rm != 4 && rm != 5 {
                counters.indirect_store[base_idx] += 1;
                prefix_len + 2
            } else if rm == 4 {
                prefix_len + 3
            } else {
                prefix_len + 6
            }
        }
        0x40 => {
            let sib = usize::from(rm == 4);
            if rm != 4 {
                counters.disp_store[base_idx] += 1;
            }
            prefix_len + 2 + sib + 1
        }
        0x80 => {
            let sib = usize::from(rm == 4);
            if rm != 4 {
                counters.disp_store[base_idx] += 1;
            }
            prefix_len + 2 + sib + 4
        }
        0xC0 => prefix_len + 2,
        _ => 1,
    }
}

fn decode_group1_imm8(bytes: &[u8], p: usize, prefix_len: usize, rex_b: bool, counters: &mut Counters) -> usize {
    let modrm = match bytes.get(p + 1) {
        Some(&b) => b,
        None => return 1,
    };
    // Only the reg-reg form (mod=11) is credited — memory-form
    // ADD/SUB/XOR happens in real code but never carries the VSP
    // bump / VIP advance / VKEY mix we care about.
    if (modrm & 0xC0) != 0xC0 {
        return 1;
    }
    let reg_ext = (modrm >> 3) & 0x07;
    let rm = modrm & 0x07;
    let target = (rm as usize) + if rex_b { 8 } else { 0 };
    match reg_ext {
        0 => counters.inc[target] += 1,
        5 => counters.dec[target] += 1,
        6 => counters.xor_imm[target] += 1,
        _ => {}
    }
    prefix_len + 3
}

fn decode_group1_imm32(bytes: &[u8], p: usize, prefix_len: usize, rex_b: bool, counters: &mut Counters) -> usize {
    let modrm = match bytes.get(p + 1) {
        Some(&b) => b,
        None => return 1,
    };
    if (modrm & 0xC0) != 0xC0 {
        return 1;
    }
    let reg_ext = (modrm >> 3) & 0x07;
    let rm = modrm & 0x07;
    let target = (rm as usize) + if rex_b { 8 } else { 0 };
    if reg_ext == 6 {
        counters.xor_imm[target] += 1;
    }
    prefix_len + 6
}

// ---------------------------------------------------------------------
// Voting
// ---------------------------------------------------------------------

fn vote_vsp(c: &Counters) -> Option<Register> {
    let totals: [u32; 16] = std::array::from_fn(|r| c.indirect_load[r].saturating_add(c.indirect_store[r]));
    let (idx, top) = argmax(&totals)?;
    if top < 4 {
        return None;
    }
    let second = second_max(&totals, idx);
    // "> 60% dominance over the runner-up": top / (top + second) > 0.6
    // <=> 2 * top > 3 * second. u64 widening avoids overflow at the
    // typical u32 counts we handle here.
    if u64::from(top) * 2 <= u64::from(second) * 3 {
        return None;
    }
    Register::from_index(idx)
}

fn vote_vip(c: &Counters) -> Option<Register> {
    // Filter out registers that look like store bases — VIP is loaded
    // from (bytecode fetch), not stored through, so an
    // indirect_store_count of 2+ disqualifies.
    let filtered: [u32; 16] = std::array::from_fn(|r| if c.indirect_store[r] < 2 { c.inc[r] } else { 0 });
    let (idx, top) = argmax(&filtered)?;
    if top < 4 {
        return None;
    }
    // Guard against a register that gets both += and -= adjustments
    // (real ADD/SUB pairs on scratch registers) rather than the
    // monotonic bump characteristic of a VIP.
    if c.inc[idx] <= c.dec[idx] {
        return None;
    }
    Register::from_index(idx)
}

fn vote_vkey(c: &Counters) -> Option<Register> {
    let (idx, top) = argmax(&c.xor_imm)?;
    if top < 2 {
        return None;
    }
    Register::from_index(idx)
}

/// Returns the (index, value) of the maximum, or `None` when the whole
/// array is zero. Ties resolve to the lowest-indexed register — the
/// dominance gate on the caller side rejects any tie loud enough to
/// matter, so the resolution rule here only affects debug-log ordering.
fn argmax(arr: &[u32; 16]) -> Option<(usize, u32)> {
    let mut best: Option<(usize, u32)> = None;
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

fn second_max(arr: &[u32; 16], skip: usize) -> u32 {
    arr.iter()
        .enumerate()
        .filter_map(|(i, &v)| if i == skip { None } else { Some(v) })
        .max()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------
// Audit-trail logging
// ---------------------------------------------------------------------

fn log_top_candidates(c: &Counters, roles: &RegisterRoles) {
    log::info!(
        "register-role vote (from {} handler bodies): vsp={:?} vip={:?} vkey={:?}",
        roles.handlers_seen,
        roles.vsp.map(|r| r.as_str()),
        roles.vip.map(|r| r.as_str()),
        roles.vkey.map(|r| r.as_str()),
    );
    log_top_three(
        "vsp",
        &std::array::from_fn(|r| c.indirect_load[r] + c.indirect_store[r]),
    );
    log_top_three("vip", &c.inc);
    log_top_three("vkey", &c.xor_imm);
}

fn log_top_three(role: &str, arr: &[u32; 16]) {
    let mut indexed: Vec<(usize, u32)> = arr.iter().copied().enumerate().filter(|&(_, v)| v > 0).collect();
    indexed.sort_by_key(|entry| std::cmp::Reverse(entry.1));
    let top: Vec<String> = indexed
        .into_iter()
        .take(3)
        .filter_map(|(i, v)| Register::from_index(i).map(|r| format!("{}={}", r.as_str(), v)))
        .collect();
    if top.is_empty() {
        log::info!("  {}: no signal", role);
    } else {
        log::info!("  {}: top {}", role, top.join(", "));
    }
}

#[cfg(test)]
#[path = "register_roles_tests.rs"]
mod tests;
