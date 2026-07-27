//! Deterministic synthetic-sample builder for end-to-end tool validation.
//!
//! Emits an on-disk PE that this crate's own detector, classifier, and
//! register-role voter SHOULD identify as a well-formed (but toy)
//! VMP-shaped binary. Not a substitute for real samples — the crypto
//! and mutation layers are intentionally absent — but it validates
//! that the whole detection stack is wired correctly and that the
//! family / version / dispatch-table / register-roles / semantic
//! pipeline agrees end-to-end.
//!
//! # What the emitted PE contains
//!
//! - A minimal PE32 (`x86`) or PE32+ (`x64`) header with the section
//!   layout the target version expects (see the constants in
//!   [`SectionLayoutMode`]). For VMP 3.6+ the executable code section
//!   has `IMAGE_SCN_MEM_EXECUTE` set so the structural-dispatcher
//!   fingerprint scan considers it.
//! - An entry stub at `AddressOfEntryPoint` shaped as `push imm32;
//!   call rel32`, with `rel32` computed so the call lands inside the
//!   VMP section (or anywhere valid for VMP 3.0, whose section layout
//!   is `Neither`).
//! - The literal strings `"VMProtect"` and `"ZwProtectVirtualMemory"`
//!   in `.rdata` (the VMP-3.x-era API marker).
//! - A structural dispatcher chain in `.text`
//!   (`mov r,[VIP]; xor r,imm; add r,r; jmp [r]`) — the four-primitive
//!   window that [`crate::protector_signals::scan_rx_sections_for_dispatcher`]
//!   picks up even when section names are scrubbed.
//! - 256 pointer-sized dispatch-table entries, each pointing at one of
//!   ~30 unique handler bodies (cycled to fill all 256 slots).
//! - Handler shells shaped to trigger specific
//!   [`VmpSemantic`] categories (Rdtsc / Cpuid / Vmexit / Nand / Nor /
//!   PushImm / Add / Popreg / Ldd / Vjmp / Popf) with a byte-for-byte
//!   match against the matcher shapes in
//!   [`crate::handler_semantic`], and to make the register-role vote
//!   converge on a specific (VSP, VIP, VKEY) triple.
//!
//! # What the emitted PE does NOT contain
//!
//! - Real VMP opcode/operand crypto — dispatch entries are stored
//!   unencrypted (XOR key = 0), which the static
//!   [`crate::XorKeyAnalyzer`] fallback recognises as the
//!   "no encryption" case.
//! - Real handler mutation / junk envelope — handlers are byte-perfect
//!   matches for the matcher shapes rather than the 0-3-junk-per-step
//!   VMP 3.x emissions.
//! - Anti-debug / anti-VM code.
//!
//! Live samples remain the ground truth; this generator's role is to
//! close the "can we even verify our own pipeline" gap
//! (`RESEARCH_GAPS.md` §7 item #9) before real corpora are available.

use crate::pe_loader::test_util::build_minimal_pe_with_section_characteristics;
use crate::{handler_semantic::VmpSemantic, protector::ProtectorFamily, register_roles::Register, version::VmpVersion};
use std::path::Path;

#[path = "synthetic_sample_handlers.rs"]
mod handlers;

// ---------------------------------------------------------------------
// PE section-characteristic constants
//
// Duplicated from `version_matchers` to keep this module self-contained
// (they're `pub(crate)` there but tying a feature-gated public builder
// to that path would drag the version-matcher module surface into every
// consumer's error output on typos).
// ---------------------------------------------------------------------
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
/// R+X code section (`.text`, `.vmp*` handler storage).
const CHARS_RX_CODE: u32 = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;
/// R-only initialised-data section (`.rdata`).
const CHARS_R_DATA: u32 = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

/// PE layout policy — how many sections we emit and in what shape.
///
/// The three variants map 1:1 to the three presets exposed publicly.
/// Which `.vmp*` sections (if any) are present is what
/// [`crate::version::VersionDetector`] keys on to discriminate VMP
/// versions, so any change here shifts the expected version verdict.
#[derive(Debug, Clone)]
enum SectionLayoutMode {
    /// `.text` + `.rdata`. No `.vmp*` — matches the `Neither` layout
    /// the detector expects for VMP 3.0-3.4. Dispatch table + handler
    /// bodies live inside `.rdata`.
    Vmp30,
    /// `.text` + `.rdata` + one VMP section. The VMP section holds the
    /// dispatch table and handler bodies; the entry stub's `call
    /// rel32` is aimed at its RVA so the `SectionLayout::OneOf` +
    /// "lands in vmp" bonuses fire.
    Vmp36Plus { vmp_section_name: String },
}

/// A synthetic-sample recipe together with the verdict the pipeline
/// should produce when handed the emitted PE. See the module doc for
/// what the emitted PE actually contains.
#[derive(Debug, Clone)]
pub struct SyntheticSample {
    /// The protector family the tool must classify the PE as (always
    /// [`ProtectorFamily::VmProtect`] for the presets, but exposed as
    /// a field so a future variant can flip it for renamed-section
    /// stress tests).
    pub expected_family: ProtectorFamily,
    /// The VMP version bucket the tool must land on.
    pub expected_version: VmpVersion,
    /// The register the tool's VSP voter must pick — see
    /// [`crate::register_roles`].
    pub expected_vsp: Register,
    /// The register the VIP voter must pick.
    pub expected_vip: Register,
    /// The register the VKEY voter must pick, or `None` when the
    /// preset intentionally emits no XOR-imm signal.
    pub expected_vkey: Option<Register>,
    /// The set of semantic categories the recipe plants handlers for.
    /// Every entry here must appear in the CLI's `--export-analysis`
    /// output on the emitted PE.
    pub expected_handler_semantics: Vec<VmpSemantic>,
    /// x86 vs x86-64. Selects both header magic bytes and the handler
    /// byte templates (REX-prefixed for x64, bare for x86).
    is_64: bool,
    /// PE `ImageBase`. Chosen to match the default of each bitness
    /// (`0x00400000` for x86, `0x140000000` for x64).
    image_base: u64,
    /// Section-layout policy — see [`SectionLayoutMode`].
    layout: SectionLayoutMode,
}

// ---------------------------------------------------------------------
// Fixed layout parameters
//
// The RVA of each section, and the offsets of subregions within each
// section, are hard-coded rather than derived from the header's
// SectionAlignment / FileAlignment fields. This keeps the entry-stub
// rel32 and dispatch-table pointer math deterministic across builds.
// The helper `assert_section_body_size` verifies at build time that
// the assembled body respects the declared size, so a size mismatch is
// caught before the PE is emitted.
// ---------------------------------------------------------------------

/// Section RVA for `.text` (both x86 and x64). Matches the
/// `SectionAlignment` PE fixture builder uses.
const TEXT_RVA: u32 = 0x1000;
/// Section RVA for `.rdata` — always immediately after `.text`.
const RDATA_RVA: u32 = 0x2000;
/// Section RVA for the VMP section in [`SectionLayoutMode::Vmp36Plus`].
const VMP_SECTION_RVA_VMP36: u32 = 0x3000;
/// `.text` body size (padding included). Fixed so `RDATA_RVA` is
/// deterministic.
const TEXT_SIZE: usize = 0x400;
/// `.rdata` body size for the Vmp36+ layout: strings only.
const RDATA_SIZE_VMP36: usize = 0x400;
/// `.rdata` body size for the Vmp30 layout: strings + dispatch table +
/// handler bodies. Larger than the Vmp36+ variant.
const RDATA_SIZE_VMP30: usize = 0x3000;
/// VMP section body size (dispatch table + handler bodies + padding).
const VMP_SIZE: usize = 0x2000;
/// Offset within the dispatch-table-holding section at which the
/// dispatch table starts. In Vmp30 this leaves room for the strings at
/// offset 0; in Vmp36+ it starts at offset 0 of the VMP section.
const DISPATCH_TABLE_OFFSET_VMP30: usize = 0x100;
const DISPATCH_TABLE_OFFSET_VMP36: usize = 0x000;
/// Number of dispatch table entries. Fixed at 256 — that's the byte
/// range of a single VMP opcode dispatch.
const DISPATCH_ENTRIES: usize = 256;
/// Space reserved per handler body inside the dispatch-table-holding
/// section. All handler bodies fit comfortably in 128 bytes; the
/// remaining space is padded with `0x90` (NOP) so the 100-byte read
/// [`crate::handler_classifier::HandlerClassifier`] performs never
/// crosses into an adjacent handler's body.
const HANDLER_SLOT_SIZE: usize = 128;

impl SyntheticSample {
    /// Preset: VMP 3.0-3.4, x86-64. VSP=r14, VIP=r15, VKEY=r11.
    ///
    /// No `.vmp*` sections — the detector must reach VMP-30 via the
    /// `SectionLayout::Neither` branch, the `push imm32; call rel32`
    /// entry stub, and the `.text/.rdata` presence rule.
    pub fn vmp30_x64_preset() -> Self {
        Self {
            expected_family: ProtectorFamily::VmProtect,
            expected_version: VmpVersion::Vmp30,
            expected_vsp: Register::R14,
            expected_vip: Register::R15,
            expected_vkey: Some(Register::R11),
            expected_handler_semantics: default_semantics(),
            is_64: true,
            image_base: 0x1_4000_0000,
            layout: SectionLayoutMode::Vmp30,
        }
    }

    /// Preset: VMP 3.0-3.4, x86. VSP=esi, VIP=edi, VKEY=ebx.
    pub fn vmp30_x86_preset() -> Self {
        Self {
            expected_family: ProtectorFamily::VmProtect,
            expected_version: VmpVersion::Vmp30,
            expected_vsp: Register::Rsi,
            expected_vip: Register::Rdi,
            expected_vkey: Some(Register::Rbx),
            expected_handler_semantics: default_semantics(),
            is_64: false,
            image_base: 0x0040_0000,
            layout: SectionLayoutMode::Vmp30,
        }
    }

    /// Preset: VMP 3.6+, x86-64. VSP=r14, VIP=r15, VKEY=r11. Uses a
    /// single `.vmp1` section — `.vmp0` alone would cause the version
    /// detector's `Vmp2` candidate to tie with `Vmp36+` (the array-
    /// order tiebreaker resolves the tie toward `Vmp2` in that shape).
    pub fn vmp36_x64_preset() -> Self {
        Self {
            expected_family: ProtectorFamily::VmProtect,
            expected_version: VmpVersion::Vmp36Plus,
            expected_vsp: Register::R14,
            expected_vip: Register::R15,
            expected_vkey: Some(Register::R11),
            expected_handler_semantics: default_semantics(),
            is_64: true,
            image_base: 0x1_4000_0000,
            layout: SectionLayoutMode::Vmp36Plus {
                vmp_section_name: ".vmp1".to_string(),
            },
        }
    }

    /// Override the name of the VMP section (only valid for
    /// [`SectionLayoutMode::Vmp36Plus`]). Used by the renamed-section
    /// test — with the section named e.g. `.custom`, the section-name
    /// rules never fire and the structural-dispatcher fingerprint in
    /// `.text` is what has to carry the VmProtect verdict.
    ///
    /// Calling this on a Vmp30 preset (which has no VMP section) is a
    /// no-op — it's exposed uniformly to keep the caller test-code
    /// tidy.
    pub fn with_vmp_section_name(mut self, name: &str) -> Self {
        if let SectionLayoutMode::Vmp36Plus {
            ref mut vmp_section_name,
        } = self.layout
        {
            *vmp_section_name = name.to_string();
        }
        self
    }

    /// Emit the fully-formed synthetic PE to `path`. Overwrites `path`
    /// if it exists.
    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        let bytes = self.assemble_pe_bytes();
        std::fs::write(path, &bytes)
    }

    /// Build the PE image in memory. Split out so the two integration
    /// tests can inspect the raw bytes without touching the filesystem
    /// if they ever want to (currently they all `write` + spawn CLI).
    fn assemble_pe_bytes(&self) -> Vec<u8> {
        let handler_bodies = handlers::build_handler_slots(self.is_64, HANDLER_SLOT_SIZE);
        // Every 128-byte slot holds one handler; entries cycle so all
        // 256 dispatch slots point at a valid handler even if we only
        // planted ~30 unique bodies.
        let handler_slot_count = handler_bodies.len() / HANDLER_SLOT_SIZE;
        let handler_count = handler_slot_count.max(1);

        // Assemble sections. The VMP section is only present in the
        // Vmp36+ layout; in Vmp30 the dispatch table + handlers live
        // in `.rdata` instead.
        let text = self.build_text_section();
        let (rdata, vmp_section) = self.build_data_sections(&handler_bodies, handler_count);

        let mut section_specs: Vec<(String, Vec<u8>, u32)> = vec![
            (".text".to_string(), text, CHARS_RX_CODE),
            (".rdata".to_string(), rdata, CHARS_R_DATA),
        ];
        if let Some((name, body)) = vmp_section {
            section_specs.push((name, body, CHARS_RX_CODE));
        }

        let borrowed: Vec<(&str, &[u8], u32)> = section_specs
            .iter()
            .map(|(name, body, chars)| (name.as_str(), body.as_slice(), *chars))
            .collect();
        let binary = build_minimal_pe_with_section_characteristics(self.is_64, self.image_base, &borrowed);
        binary.data
    }

    /// Compute the (image-base-relative) VA of handler slot `slot_index`.
    ///
    /// Handlers live either at the tail of `.rdata` (Vmp30 layout) or
    /// at the tail of the VMP section (Vmp36+), starting immediately
    /// after the 256-entry dispatch table.
    fn handler_va(&self, slot_index: usize) -> u64 {
        let section_rva = match self.layout {
            SectionLayoutMode::Vmp30 => RDATA_RVA,
            SectionLayoutMode::Vmp36Plus { .. } => VMP_SECTION_RVA_VMP36,
        };
        let dispatch_offset = match self.layout {
            SectionLayoutMode::Vmp30 => DISPATCH_TABLE_OFFSET_VMP30,
            SectionLayoutMode::Vmp36Plus { .. } => DISPATCH_TABLE_OFFSET_VMP36,
        };
        let handlers_base = dispatch_offset + DISPATCH_ENTRIES * self.pointer_size();
        self.image_base + section_rva as u64 + (handlers_base + slot_index * HANDLER_SLOT_SIZE) as u64
    }

    fn pointer_size(&self) -> usize {
        if self.is_64 {
            8
        } else {
            4
        }
    }

    /// Compose the `.text` section body: entry stub, 6 bytes of NOPs,
    /// then the structural dispatcher chain, then NOP padding out to
    /// [`TEXT_SIZE`].
    fn build_text_section(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(TEXT_SIZE);
        let call_target_rva = match self.layout {
            // For Vmp30, `Neither`-layout rules fire regardless of
            // where the call lands — target the top of `.rdata`, which
            // is always present.
            SectionLayoutMode::Vmp30 => RDATA_RVA,
            SectionLayoutMode::Vmp36Plus { .. } => VMP_SECTION_RVA_VMP36,
        };
        // `push imm32`: value is arbitrary. `call rel32` next_instr_va
        // is `entry_va + 10`; rel32 must send control to
        // `image_base + call_target_rva`.
        let next_instr_rva = TEXT_RVA + 10;
        let rel32 = (call_target_rva as i64 - next_instr_rva as i64) as i32;
        body.extend_from_slice(&[0x68, 0x00, 0x00, 0x00, 0x00]);
        body.push(0xE8);
        body.extend_from_slice(&rel32.to_le_bytes());
        // 6 bytes of scratch NOPs.
        body.extend_from_slice(&[0x90; 6]);
        // Structural dispatcher chain (see the module doc for the four
        // primitives the scan looks for). Placed a fixed 22 bytes past
        // the entry so it never overlaps the entry stub's own bytes.
        body.extend_from_slice(&handlers::structural_dispatcher_bytes(self.is_64));
        // Pad remainder with 0x90.
        while body.len() < TEXT_SIZE {
            body.push(0x90);
        }
        assert_section_body_size(".text", body.len(), TEXT_SIZE);
        body
    }

    /// Compose `.rdata` and (optionally) the VMP section.
    ///
    /// For Vmp30 both the strings AND the dispatch table + handlers
    /// live in `.rdata`. For Vmp36+ `.rdata` holds only the strings
    /// and the returned `Option` carries the VMP section body.
    fn build_data_sections(&self, handler_bodies: &[u8], handler_count: usize) -> (Vec<u8>, Option<(String, Vec<u8>)>) {
        let strings = strings_bytes();

        match &self.layout {
            SectionLayoutMode::Vmp30 => {
                let mut rdata = strings.clone();
                while rdata.len() < DISPATCH_TABLE_OFFSET_VMP30 {
                    rdata.push(0);
                }
                self.write_dispatch_and_handlers(&mut rdata, handler_bodies, handler_count);
                while rdata.len() < RDATA_SIZE_VMP30 {
                    rdata.push(0);
                }
                assert_section_body_size(".rdata", rdata.len(), RDATA_SIZE_VMP30);
                (rdata, None)
            }
            SectionLayoutMode::Vmp36Plus { vmp_section_name } => {
                let mut rdata = strings.clone();
                while rdata.len() < RDATA_SIZE_VMP36 {
                    rdata.push(0);
                }
                assert_section_body_size(".rdata", rdata.len(), RDATA_SIZE_VMP36);

                let mut vmp = Vec::with_capacity(VMP_SIZE);
                self.write_dispatch_and_handlers(&mut vmp, handler_bodies, handler_count);
                while vmp.len() < VMP_SIZE {
                    vmp.push(0x90);
                }
                assert_section_body_size(vmp_section_name, vmp.len(), VMP_SIZE);
                (rdata, Some((vmp_section_name.clone(), vmp)))
            }
        }
    }

    /// Append the 256 dispatch-table pointers followed by the handler
    /// bodies. Entries beyond `handler_count - 1` wrap around so all
    /// 256 slots point at real handler VAs.
    fn write_dispatch_and_handlers(&self, out: &mut Vec<u8>, handler_bodies: &[u8], handler_count: usize) {
        for i in 0..DISPATCH_ENTRIES {
            let handler_slot = i % handler_count;
            let va = self.handler_va(handler_slot);
            if self.is_64 {
                out.extend_from_slice(&va.to_le_bytes());
            } else {
                out.extend_from_slice(&(va as u32).to_le_bytes());
            }
        }
        out.extend_from_slice(handler_bodies);
    }
}

/// The literal string markers embedded in `.rdata`.
///
/// `"VMProtect"` bumps the family score by +15 and also lifts the
/// version detector's `Vmp1` candidate by +15 (harmless; the entry
/// stub's Vmp30 bonus is much larger). `"ZwProtectVirtualMemory"` is
/// the VMP-3.x-era API marker — +15 to family score AND +10 each to
/// the Vmp30/Vmp35/Vmp36+ version candidates.
fn strings_bytes() -> Vec<u8> {
    let mut s = b"VMProtect\0".to_vec();
    s.extend_from_slice(b"ZwProtectVirtualMemory\0");
    s
}

/// Panics if the assembled section body would exceed its planned size.
/// A panic here means the templates in [`handlers`] grew past the
/// budget without the constants being bumped in tandem.
fn assert_section_body_size(name: &str, actual: usize, expected: usize) {
    assert!(
        actual <= expected,
        "synthetic sample section `{name}` overflowed its planned size: {actual} > {expected} bytes",
    );
}

/// Handler-semantic categories that the preset recipes plant handlers
/// for. Every entry here must appear in the CLI's `--export-analysis`
/// output on the emitted PE.
fn default_semantics() -> Vec<VmpSemantic> {
    vec![
        VmpSemantic::Rdtsc,
        VmpSemantic::Cpuid,
        VmpSemantic::Vmexit,
        VmpSemantic::Nand,
        VmpSemantic::Nor,
        VmpSemantic::PushImm,
        VmpSemantic::Add,
        VmpSemantic::Popreg,
        VmpSemantic::Ldd,
        VmpSemantic::Vjmp,
        VmpSemantic::Popf,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmp36_x64_preset_writes_valid_pe_bytes() {
        // Sanity check: the assembled bytes must parse as a valid PE
        // via goblin without hitting any bounds errors.
        let sample = SyntheticSample::vmp36_x64_preset();
        let bytes = sample.assemble_pe_bytes();
        assert!(bytes.len() > 0x1000);
        let pe = goblin::pe::PE::parse(&bytes).expect("assembled bytes must parse as PE");
        assert!(pe.is_64);
        assert_eq!(pe.sections.len(), 3);
    }

    #[test]
    fn vmp30_x86_preset_writes_valid_pe_bytes() {
        let sample = SyntheticSample::vmp30_x86_preset();
        let bytes = sample.assemble_pe_bytes();
        let pe = goblin::pe::PE::parse(&bytes).expect("assembled bytes must parse as PE");
        assert!(!pe.is_64);
        assert_eq!(pe.sections.len(), 2);
    }

    #[test]
    fn renamed_vmp_section_is_reflected_in_pe() {
        let sample = SyntheticSample::vmp36_x64_preset().with_vmp_section_name(".custom");
        let bytes = sample.assemble_pe_bytes();
        let pe = goblin::pe::PE::parse(&bytes).expect("assembled bytes must parse as PE");
        let names: Vec<String> = pe
            .sections
            .iter()
            .map(|s| {
                std::str::from_utf8(&s.name)
                    .unwrap_or("")
                    .trim_end_matches('\0')
                    .to_string()
            })
            .collect();
        assert!(names.iter().any(|n| n == ".custom"));
        assert!(!names.iter().any(|n| n == ".vmp1"));
    }
}
