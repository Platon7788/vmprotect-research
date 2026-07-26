//! Matcher primitives used by [`crate::version::VersionDetector`].
//!
//! Split out of `version.rs` to keep that file under the crate's line-count
//! convention. Everything here is `pub(crate)` — these are implementation
//! details of version detection, not part of the crate's public API.

/// IMAGE_SCN_MEM_EXECUTE
pub(crate) const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// IMAGE_SCN_MEM_READ
pub(crate) const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
/// IMAGE_SCN_MEM_WRITE
pub(crate) const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const RWX_MASK: u32 = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

/// True if the given `Characteristics` value has read+write+execute set.
pub(crate) fn is_rwx(characteristics: u32) -> bool {
    characteristics & RWX_MASK == RWX_MASK
}

// ---------------------------------------------------------------------
// Entry stub byte-pattern matching
// ---------------------------------------------------------------------

/// PUSHAD (VMP1 entry stubs commonly start with this).
pub(crate) const PUSHAD: [Option<u8>; 1] = [Some(0x60)];
/// `mov esi, imm32`
pub(crate) const MOV_ESI_IMM32: [Option<u8>; 5] = [Some(0xBE), None, None, None, None];
/// `lea edi, [esi+disp32]`
pub(crate) const LEA_EDI_ESI_DISP32: [Option<u8>; 6] = [Some(0x8D), Some(0xBE), None, None, None, None];
/// `push imm32`
pub(crate) const PUSH_IMM32: [Option<u8>; 5] = [Some(0x68), None, None, None, None];
/// `call rel32`
pub(crate) const CALL_REL32: [Option<u8>; 5] = [Some(0xE8), None, None, None, None];
/// `jmp rel32`
pub(crate) const JMP_REL32: [Option<u8>; 5] = [Some(0xE9), None, None, None, None];

/// Result of scanning an entry stub for the classic "push imm32; call/jmp
/// rel32" shape used by VMP 2.x and VMP 3.x.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PushCallJmpMatch {
    /// Offset (from the start of the scanned window) of the `push` opcode.
    pub(crate) push_offset: usize,
    /// True if the branch is a `call`, false if it is a `jmp`.
    pub(crate) is_call: bool,
    /// Signed 32-bit displacement encoded in the branch instruction.
    pub(crate) rel32: i32,
}

/// Result of scanning an entry stub for the VMP1 "pushad; mov esi, imm32"
/// shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Vmp1StubMatch {
    pub(crate) has_pushad: bool,
    pub(crate) has_mov_esi_imm32: bool,
    pub(crate) has_lea_edi_esi: bool,
}

/// Matches fixed-length byte patterns with wildcard bytes (`None`) against
/// entry-point code.
pub(crate) struct EntryStubMatcher;

impl EntryStubMatcher {
    /// Returns true if `data` starts with `pattern`, treating `None` entries
    /// in `pattern` as wildcards. False if `data` is shorter than `pattern`.
    pub(crate) fn matches(data: &[u8], pattern: &[Option<u8>]) -> bool {
        if data.len() < pattern.len() {
            return false;
        }
        data.iter().zip(pattern.iter()).all(|(byte, expected)| match expected {
            Some(want) => byte == want,
            None => true,
        })
    }

    /// Searches for `pattern` at any offset within the first `window` bytes
    /// of `data`, returning the offset of the first match.
    pub(crate) fn find(data: &[u8], pattern: &[Option<u8>], window: usize) -> Option<usize> {
        let limit = window.min(data.len());
        (0..limit).find(|&offset| Self::matches(&data[offset..], pattern))
    }

    /// Scans for a VMP1-style stub: PUSHAD at the very start of `data`,
    /// followed within `window` bytes by `mov esi, imm32` and/or
    /// `lea edi, [esi+disp32]`.
    pub(crate) fn find_vmp1_stub(data: &[u8], window: usize) -> Vmp1StubMatch {
        let has_pushad = Self::matches(data, &PUSHAD);
        if !has_pushad || data.len() <= 1 {
            return Vmp1StubMatch::default();
        }

        let tail = &data[1..];
        Vmp1StubMatch {
            has_pushad,
            has_mov_esi_imm32: Self::find(tail, &MOV_ESI_IMM32, window).is_some(),
            has_lea_edi_esi: Self::find(tail, &LEA_EDI_ESI_DISP32, window).is_some(),
        }
    }

    /// Scans for a `push imm32` immediately followed by `call rel32` or
    /// `jmp rel32`, anywhere within the first `window` bytes of `data`.
    pub(crate) fn find_push_call_jmp(data: &[u8], window: usize) -> Option<PushCallJmpMatch> {
        let limit = window.min(data.len());
        for push_offset in 0..limit {
            if !Self::matches(&data[push_offset..], &PUSH_IMM32) {
                continue;
            }
            let branch_offset = push_offset + 5;
            if branch_offset >= data.len() {
                continue;
            }
            let branch = &data[branch_offset..];
            let is_call = if Self::matches(branch, &CALL_REL32) {
                true
            } else if Self::matches(branch, &JMP_REL32) {
                false
            } else {
                continue;
            };
            let rel32 = i32::from_le_bytes([branch[1], branch[2], branch[3], branch[4]]);
            return Some(PushCallJmpMatch {
                push_offset,
                is_call,
                rel32,
            });
        }
        None
    }
}

// ---------------------------------------------------------------------
// Section layout classification
// ---------------------------------------------------------------------

/// Classification of a binary's `.vmp0`/`.vmp1` section layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SectionLayout {
    /// Both `.vmp0` and `.vmp1` present (VMP 3.5.x signature).
    Both,
    /// Exactly one of `.vmp0` / `.vmp1` present (VMP 2.x or 3.6+ signature).
    OneOf,
    /// Neither section present (VMP 1.x, 3.0-3.4, or non-VMP binary).
    Neither,
}

/// Classifies binaries by `.vmp0`/`.vmp1` presence.
pub(crate) struct SectionLayoutMatcher;

impl SectionLayoutMatcher {
    /// Classify a section layout from `.vmp0`/`.vmp1` presence flags.
    pub(crate) fn classify(has_vmp0: bool, has_vmp1: bool) -> SectionLayout {
        match (has_vmp0, has_vmp1) {
            (true, true) => SectionLayout::Both,
            (true, false) | (false, true) => SectionLayout::OneOf,
            (false, false) => SectionLayout::Neither,
        }
    }
}
