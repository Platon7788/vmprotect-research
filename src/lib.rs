#![warn(dead_code)]
#![warn(unused_variables)]
#![warn(missing_docs)]

//! VMP Devirtualizer - Production Core
//!
//! Supports VMProtect versions 1.0 → 3.10.5
//!
//! # Architecture
//! - PE loader: Binary parsing, VA mapping
//! - Version detector: Identify VMP version
//! - Opcode table: Dispatch table management
//! - Bytecode decoder: Instruction parsing
//! - Operand decryption: CRC-based decryption
//! - ALU reconstructor: NOR/NAND → arithmetic

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

pub mod alu;
pub mod bytecode;
pub mod decrypt;
pub mod dispatch_extractor_py;
pub mod dispatch_table;
pub mod handler_classifier;
pub mod handler_semantic;
pub mod junk_stripper;
pub mod opcode_table;
pub mod pe_loader;
pub mod protector;
mod protector_matchers;
mod protector_signals;
pub mod register_roles;
#[cfg(feature = "synthetic-samples")]
pub mod synthetic_sample;
pub mod version;
mod version_matchers;
pub mod xor_key_analyzer;

pub use alu::{ALUOp, ALUReconstructor};
pub use bytecode::Bytecode;
pub use decrypt::{CryptoScheme, OpcodeCryptor};
// Deliberately NOT re-exported at the crate root:
//   - dispatch_extractor_py::{DispatchEntry, DispatchExtractorPy}
// The Python-subprocess extractor is an internal orchestration seam
// scheduled for elimination (AUDIT_REPORT.md Q15). Reaching it via the
// long path `vmp_devirt::dispatch_extractor_py::*` keeps the future
// pure-Rust replacement from being a semver break for any external
// consumer who happened to grab the type off the crate root.
pub use dispatch_table::DispatchTableLocator;
pub use handler_classifier::{HandlerClassification, HandlerClassifier};
pub use handler_semantic::{SemanticMatcher, VmpSemantic};
pub use opcode_table::{Handler, OpcodeTable};
pub use pe_loader::{Bitness, PEBinary};
pub use protector::{ProtectorDetector, ProtectorFamily, ProtectorReport};
pub use register_roles::{Register, RegisterRoles};
pub use version::{VersionDetector, VmpVersion, VmpVersionDetail};
pub use xor_key_analyzer::{XorKeyAnalyzer, XorKeyEntry};

/// Main VMP Devirtualizer
pub struct VmpDevirtualizer {
    binary: PEBinary,
    version: VmpVersion,
    version_confidence: u8,
    opcode_table: OpcodeTable,
    dispatch_table_va: Option<u64>,
    handler_classifications: Vec<HandlerClassification>,
    /// Result of the register-role vote across all extracted handler
    /// bodies. Populated once during construction; defaults (all
    /// `None`) when no dispatch table was located or extraction
    /// failed, so callers can still access it unconditionally.
    register_roles: RegisterRoles,
    /// Reused across every `devirtualize_range` call so pattern lookups
    /// don't rebuild the NOR/NAND pattern table per call.
    alu_reconstructor: ALUReconstructor,
}

impl VmpDevirtualizer {
    /// Load binary and detect VMP version
    pub fn new(binary_path: impl AsRef<Path>) -> Result<Self> {
        Self::new_with_hint(binary_path, None)
    }

    /// Load binary and detect VMP version, optionally seeding dispatch-table
    /// location with a caller-supplied RVA hint.
    ///
    /// The hint is only used if it validates as a plausible dispatch table
    /// (see [`DispatchTableLocator::locate`]); otherwise location falls back
    /// to scanning candidate sections as usual.
    pub fn new_with_hint(binary_path: impl AsRef<Path>, dispatch_rva_hint: Option<u64>) -> Result<Self> {
        let binary = PEBinary::load(binary_path).context("Failed to load PE binary")?;

        // Q — Part B: use `detect_detailed` so sub-version hints reach
        // the audit log. `detect` remains part of the public surface
        // for consumers that only need the coarse bucket, but the
        // devirtualiser itself never wants to discard the hint list.
        let (version_detail, version_confidence) =
            VersionDetector::detect_detailed(&binary).context("Failed to detect VMP version")?;
        let version = version_detail.version;
        for hint in &version_detail.sub_hints {
            log::info!("VMP sub-version hint: {}", hint);
        }

        let mut opcode_table = OpcodeTable::new();
        let mut dispatch_table_va = None;
        let mut handler_classifications = Vec::new();
        let mut register_roles = RegisterRoles::default();

        // Try to locate and extract dispatch table
        match DispatchTableLocator::locate(&binary, dispatch_rva_hint) {
            Ok(dt_va) => {
                log::info!("Found dispatch table at VA: 0x{:x}", dt_va);
                dispatch_table_va = Some(dt_va);

                // Extract all 256 handler addresses
                match DispatchTableLocator::extract_handlers(&binary, dt_va) {
                    Ok(handlers) => {
                        log::info!("Extracted {} handler addresses", handlers.len());

                        // Validate dispatch table
                        match DispatchTableLocator::validate(&binary, &handlers) {
                            Ok(true) => {
                                log::info!("Dispatch table validation passed");

                                // Classify all handlers
                                match HandlerClassifier::classify_all_and_bodies(&binary, &handlers) {
                                    Ok((classifications, bodies)) => {
                                        log::info!("Classified {} handlers", classifications.len());

                                        // Populate opcode table with classifications
                                        for (opcode, classification) in classifications.iter().enumerate() {
                                            if opcode <= 255 {
                                                opcode_table.register(
                                                    opcode as u8,
                                                    Handler {
                                                        name: classification.handler_type.clone(),
                                                        opcode: opcode as u8,
                                                        size_bytes: Some(classification.size),
                                                    },
                                                );
                                            }
                                        }

                                        handler_classifications = classifications;

                                        // Vote on register roles from the
                                        // same handler-body prefixes the
                                        // classifier already saw — cheaper
                                        // than a second section-read pass
                                        // and keeps the byte-window we
                                        // analyse consistent across layers.
                                        if let Ok(bitness) = binary.bitness() {
                                            register_roles = register_roles::analyse_handlers(&bodies, bitness);
                                        }
                                    }
                                    Err(e) => {
                                        log::warn!("Failed to classify handlers: {}", e);
                                    }
                                }
                            }
                            Ok(false) => {
                                log::warn!("Dispatch table validation failed");
                            }
                            Err(e) => {
                                log::warn!("Error validating dispatch table: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to extract handlers: {}", e);
                    }
                }
            }
            Err(e) => {
                // `e`'s chain can bottom out in `DispatchTableLocator`'s
                // pattern-scan bail, which embeds a PE section name — an
                // attacker-controlled byte string. Sanitise the whole
                // rendered chain defensively so a crafted section name can
                // never inject ANSI/CR/LF into this log line, even if a
                // future refactor changes which error propagates here.
                log::warn!(
                    "Failed to locate dispatch table: {}",
                    pe_loader::sanitise_section_name(&e.to_string())
                );
            }
        }

        Ok(VmpDevirtualizer {
            binary,
            version,
            version_confidence,
            opcode_table,
            dispatch_table_va,
            handler_classifications,
            register_roles,
            alu_reconstructor: ALUReconstructor::new(),
        })
    }

    /// Get detected VMP version
    pub fn version(&self) -> VmpVersion {
        self.version
    }

    /// Override the detected VMP version.
    ///
    /// Intended for `--force-version` research scenarios where the detector
    /// picks Unknown but the analyst knows the sample's true version. Does
    /// not touch the confidence score — callers that care can inspect it.
    pub fn force_version(&mut self, version: VmpVersion) {
        self.version = version;
    }

    /// Get detected VMP version confidence (0-100)
    pub fn version_confidence(&self) -> u8 {
        self.version_confidence
    }

    /// Returns `false` when the loaded binary shows no signs of being a
    /// VMP-protected image: the version detector landed on `Unknown` with
    /// confidence below the 40-point threshold, AND no dispatch table
    /// was located.
    ///
    /// This is the library-side spelling of the F2 non-VMP gate the CLI
    /// applies before running `devirtualize_range`. Any wrapper —
    /// batch harness, GUI, fuzzer — should reuse this instead of
    /// re-implementing the predicate against public accessors, so the
    /// tunable confidence threshold only lives here.
    ///
    /// A `--force-version` override bumps `version()` off `Unknown` and
    /// therefore flips this to `true`; a `--dispatch-rva` hint that
    /// validates gives `dispatch_table_va()` a value and does the same.
    /// Both bypasses are intentional research escape hatches.
    pub fn looks_like_vmp(&self) -> bool {
        !(self.version == VmpVersion::Unknown && self.version_confidence < 40 && self.dispatch_table_va.is_none())
    }

    /// Get PE binary reference
    pub fn binary(&self) -> &PEBinary {
        &self.binary
    }

    /// Get dispatch table VA
    pub fn dispatch_table_va(&self) -> Option<u64> {
        self.dispatch_table_va
    }

    /// Get handler classifications
    pub fn handler_classifications(&self) -> &[HandlerClassification] {
        &self.handler_classifications
    }

    /// Get handler statistics
    pub fn handler_statistics(&self) -> HashMap<String, usize> {
        HandlerClassifier::get_statistics(&self.handler_classifications)
    }

    /// Register-role vote result (VIP/VSP/VKEY canonicalisation).
    ///
    /// Populated during construction by
    /// [`register_roles::analyse_handlers`] over the same handler-body
    /// prefixes fed to the classifier. When no dispatch table was
    /// located, returns the default (all fields `None`).
    pub fn register_roles(&self) -> &RegisterRoles {
        &self.register_roles
    }

    /// Export opcode table as JSON
    pub fn export_opcode_table(&self, path: &str) -> Result<()> {
        self.opcode_table
            .to_json(path)
            .context("Failed to export opcode table")?;
        log::info!("Opcode table exported to: {}", path);
        Ok(())
    }

    /// Export handler classifications as JSON
    pub fn export_handler_classifications(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.handler_classifications)
            .context("Failed to serialize classifications")?;
        std::fs::write(path, json).context("Failed to write classifications file")?;
        log::info!("Handler classifications exported to: {}", path);
        Ok(())
    }

    /// Build the unified analysis report (Commit R): protector family +
    /// VMP version + dispatch table + register roles + every handler
    /// classification in one serialisable snapshot, replacing the need
    /// to cross-reference `--export-opcodes` and `--export-handlers`
    /// separately.
    ///
    /// Re-runs [`ProtectorDetector::detect`] rather than caching a
    /// `ProtectorReport` on `VmpDevirtualizer` itself: family detection
    /// is a cheap section/byte scan and every existing call site (the
    /// CLI) already runs it once before construction anyway, so adding
    /// a second field here would just be a second copy of the same
    /// data to keep in sync.
    pub fn analysis_report(&self) -> Result<AnalysisReport> {
        let protector = ProtectorDetector::detect(&self.binary).context("protector detection")?;
        let bitness = self.binary.bitness().context("determine PE bitness")?;

        let handler_count = self.handler_classifications.len();
        let matched = self
            .handler_classifications
            .iter()
            .filter(|c| c.vmp_semantic.is_some())
            .count();
        let semantic_coverage_percent = if handler_count == 0 {
            0.0
        } else {
            (matched as f64 / handler_count as f64) * 100.0
        };

        Ok(AnalysisReport {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            binary_path: self.binary.path.clone(),
            bitness,
            protector,
            vmp_version: self.version,
            vmp_version_confidence: self.version_confidence,
            // No `VmpVersionDetail`-style per-rule hint list exists yet
            // (see AUDIT_REPORT.md future work) -- left empty rather
            // than duplicating `VersionDetector::detect`'s internal
            // reason strings, which aren't exposed on its public
            // `(VmpVersion, u8)` return type today.
            vmp_version_hints: Vec::new(),
            dispatch_table_va: self.dispatch_table_va.map(|va| format!("0x{:x}", va)),
            handler_count,
            handler_classifications: self.handler_classifications.clone(),
            register_roles: self.register_roles,
            crypto_scheme: CryptoScheme::for_version(self.version).as_str().to_string(),
            semantic_coverage_percent,
        })
    }

    /// Decode instruction at VIP address.
    ///
    /// `cryptor` must be the same `OpcodeCryptor` instance used for every
    /// other instruction decoded from the same bytecode section: VMP's
    /// operand cipher is a running stream cipher, so decoding a handler in
    /// isolation with a fresh cryptor would decrypt against the wrong key.
    pub fn decode_instruction(&self, vip: u64, cryptor: &mut OpcodeCryptor) -> Result<DecodedInstruction> {
        let bytecode = Bytecode::from_vip(&self.binary, vip)?;
        let opcode_slot = bytecode.opcode_byte();

        let handler = self
            .opcode_table
            .lookup(opcode_slot)
            .context(format!("Unknown opcode: 0x{:02x}", opcode_slot))?;

        let operands = bytecode.decode_operands(&handler, cryptor)?;
        let size = bytecode.size(&handler)?;

        Ok(DecodedInstruction {
            vip,
            opcode: opcode_slot,
            handler,
            operands,
            size,
            alu_op: None,
        })
    }

    /// Devirtualize instruction range.
    ///
    /// Decodes sequentially with a single `OpcodeCryptor` seeded once from
    /// `start_vip` (never reset per handler — see `decode_instruction`),
    /// then runs a second pass reconstructing NOR/NAND ALU chains via
    /// `ALUReconstructor`.
    pub fn devirtualize_range(&self, start_vip: u64, end_vip: u64) -> Result<Vec<DecodedInstruction>> {
        let mut instructions = Vec::new();
        let mut vip = start_vip;

        // Commit M: crypto scheme is now per-version instead of the
        // pre-existing `crc*31+val` placeholder for every sample. See
        // `decrypt.rs` module doc for the extraction notes; the audit
        // trail includes both the detected version and the picked
        // scheme so log readers can spot a mis-detection.
        let scheme = CryptoScheme::for_version(self.version);
        log::info!(
            "Operand crypto: version={} -> scheme={:?}",
            self.version.as_str(),
            scheme
        );
        let mut cryptor = OpcodeCryptor::new_with_scheme(scheme);
        cryptor.init_from_section(start_vip);

        while vip < end_vip {
            match self.decode_instruction(vip, &mut cryptor) {
                Ok(instr) => {
                    vip += instr.size as u64;
                    instructions.push(instr);
                }
                Err(e) => {
                    log::warn!("Error at VIP 0x{:x}: {}", vip, e);
                    break;
                }
            }
        }

        alu::reconstruct_alu_chains(&mut instructions, &self.alu_reconstructor);

        Ok(instructions)
    }
}

/// Unified analysis export (Commit R): every layer of the pipeline's
/// findings in one serialisable snapshot, replacing the older pattern
/// of dumping `--export-opcodes` and `--export-handlers` separately
/// and leaving callers to line the two files up by hand.
///
/// Built via [`VmpDevirtualizer::analysis_report`]. `#[serde(default)]`
/// is deliberately NOT sprinkled across every field here the way it is
/// on `HandlerClassification::vmp_semantic_confidence` -- this whole
/// type is new in Commit R, so there is no pre-existing on-disk shape
/// to stay backward-compatible with.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnalysisReport {
    /// This crate's version (`CARGO_PKG_VERSION`), so a report on disk
    /// can be traced back to the tool build that produced it.
    pub tool_version: String,
    /// Path to the analysed binary, as passed to `VmpDevirtualizer::new`.
    pub binary_path: String,
    /// Target architecture (x86 / x64) of the loaded PE image.
    pub bitness: Bitness,
    /// Protector-family verdict (VMProtect / Themida / ... / Unprotected).
    pub protector: ProtectorReport,
    /// Detected VMP version (`Unknown` when the sample isn't recognised
    /// or `--force-version` hasn't been applied).
    pub vmp_version: VmpVersion,
    /// 0-100 confidence in `vmp_version`.
    pub vmp_version_confidence: u8,
    /// Per-rule version-detection hints. Always empty today -- see
    /// `analysis_report`'s doc comment for why.
    pub vmp_version_hints: Vec<String>,
    /// Dispatch table VA as a `0x`-prefixed hex string, or `None` when
    /// no dispatch table was located.
    pub dispatch_table_va: Option<String>,
    /// Number of entries in `handler_classifications`.
    pub handler_count: usize,
    /// Every extracted handler's classification, x86-level and
    /// VMP-semantic.
    pub handler_classifications: Vec<HandlerClassification>,
    /// VIP/VSP/VKEY register-role vote.
    pub register_roles: RegisterRoles,
    /// Stable name of the operand-decryption scheme picked for
    /// `vmp_version` (see [`CryptoScheme::for_version`]).
    pub crypto_scheme: String,
    /// Percentage of `handler_classifications` that got a non-`None`
    /// `vmp_semantic` (i.e. `matched / handler_count * 100`). `0.0`
    /// when `handler_count` is `0`.
    pub semantic_coverage_percent: f64,
}

/// Parse a hex string into a `u64`, accepting an optional `0x`/`0X` prefix.
///
/// Used by the CLI for both `--vip` and `--dispatch-rva` so both flags share
/// the exact same parsing rules.
pub fn parse_hex_rva(s: &str) -> Result<u64> {
    let trimmed = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(trimmed, 16).with_context(|| format!("Invalid hex value: {}", s))
}

/// Decoded instruction
#[derive(Debug, Clone)]
pub struct DecodedInstruction {
    /// Virtual instruction pointer
    pub vip: u64,
    /// Opcode slot byte
    pub opcode: u8,
    /// Handler type
    pub handler: Handler,
    /// Operand values
    pub operands: Vec<u64>,
    /// Instruction size in bytes
    pub size: usize,
    /// Reconstructed ALU operation, populated by `devirtualize_range`'s
    /// second pass on the last instruction of a NOR/NAND chain. `None` for
    /// every other instruction, including the non-final links of a chain.
    pub alu_op: Option<ALUOp>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Version detection on a minimal PE with no VMP markers must land
    /// on `Unknown` with low confidence — this pins the detector's
    /// "nothing here" behaviour, which is what F2's non-VMP-exit gate
    /// keys on. Replaces the empty stub whose comment referenced
    /// AUDIT_REPORT.md Q13 (now closed by `pe_loader::test_util`).
    #[test]
    fn version_detection_returns_unknown_for_bare_pe() {
        use crate::pe_loader::test_util::build_minimal_pe;
        let binary = build_minimal_pe(true, 0x1_4000_0000, 0x1000, &[0x90u8; 32]);
        let (version, confidence) = VersionDetector::detect(&binary).expect("detect must not error");
        assert_eq!(version, VmpVersion::Unknown);
        assert!(confidence < 40, "bare PE must be below the VMP threshold");
    }

    #[test]
    fn parse_hex_rva_accepts_0x_prefix() {
        assert_eq!(parse_hex_rva("0xabcde").unwrap(), 0xabcde);
    }

    #[test]
    fn parse_hex_rva_accepts_uppercase_0x_prefix() {
        assert_eq!(parse_hex_rva("0X1000").unwrap(), 0x1000);
    }

    #[test]
    fn parse_hex_rva_accepts_bare_hex() {
        assert_eq!(parse_hex_rva("abcde").unwrap(), 0xabcde);
    }

    #[test]
    fn parse_hex_rva_rejects_invalid_input() {
        assert!(parse_hex_rva("not-hex").is_err());
        assert!(parse_hex_rva("0xzz").is_err());
        assert!(parse_hex_rva("").is_err());
    }

    /// Commit R: `AnalysisReport` must round-trip through JSON exactly
    /// as `HandlerClassification` and friends already do -- this pins
    /// the whole aggregate export, not just its constituent types.
    ///
    /// Built by hand (not `VmpDevirtualizer::new`, which needs a real
    /// on-disk file) since this `mod tests` is a child of `lib`'s own
    /// module and can see every private field directly.
    #[test]
    fn analysis_report_serialises_and_deserialises() {
        use crate::pe_loader::test_util::build_minimal_pe;

        let binary = build_minimal_pe(true, 0x1_4000_0000, 0x1000, &[0x90u8; 32]);
        let devirt = VmpDevirtualizer {
            binary,
            version: VmpVersion::Vmp2,
            version_confidence: 80,
            opcode_table: OpcodeTable::new(),
            dispatch_table_va: Some(0x1_4000_1000),
            handler_classifications: vec![HandlerClassification {
                va: 0x1_4000_1000,
                handler_type: "MOV_REG_REG".to_string(),
                size: 3,
                confidence: 85,
                vmp_semantic: Some(VmpSemantic::Add),
                vmp_semantic_confidence: 95,
            }],
            register_roles: RegisterRoles::default(),
            alu_reconstructor: ALUReconstructor::new(),
        };

        let report = devirt.analysis_report().expect("analysis_report must not error");
        assert_eq!(report.vmp_version, VmpVersion::Vmp2);
        assert_eq!(report.handler_count, 1);
        assert_eq!(report.dispatch_table_va.as_deref(), Some("0x140001000"));
        assert_eq!(report.semantic_coverage_percent, 100.0);
        assert_eq!(report.crypto_scheme, "Vmp2Rolling");

        let json = serde_json::to_string_pretty(&report).expect("serialize AnalysisReport");
        let back: AnalysisReport = serde_json::from_str(&json).expect("deserialize AnalysisReport");
        assert_eq!(back.vmp_version, report.vmp_version);
        assert_eq!(back.handler_classifications.len(), 1);
        assert_eq!(back.handler_classifications[0].vmp_semantic, Some(VmpSemantic::Add));
        assert_eq!(back.handler_classifications[0].vmp_semantic_confidence, 95);
    }

    /// `semantic_coverage_percent` must be `0.0`, not NaN, when there
    /// are zero handlers to divide by (e.g. dispatch-table location
    /// failed entirely).
    #[test]
    fn analysis_report_handles_zero_handlers_without_nan() {
        use crate::pe_loader::test_util::build_minimal_pe;

        let binary = build_minimal_pe(true, 0x1_4000_0000, 0x1000, &[0x90u8; 32]);
        let devirt = VmpDevirtualizer {
            binary,
            version: VmpVersion::Unknown,
            version_confidence: 0,
            opcode_table: OpcodeTable::new(),
            dispatch_table_va: None,
            handler_classifications: Vec::new(),
            register_roles: RegisterRoles::default(),
            alu_reconstructor: ALUReconstructor::new(),
        };

        let report = devirt.analysis_report().expect("analysis_report must not error");
        assert_eq!(report.handler_count, 0);
        assert_eq!(report.semantic_coverage_percent, 0.0);
        assert!(report.dispatch_table_va.is_none());
    }
}
