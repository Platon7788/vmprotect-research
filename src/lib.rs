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
pub mod opcode_table;
pub mod pe_loader;
pub mod version;
mod version_matchers;
pub mod xor_key_analyzer;

pub use alu::{ALUOp, ALUReconstructor};
pub use bytecode::Bytecode;
pub use decrypt::OpcodeCryptor;
pub use dispatch_extractor_py::{DispatchEntry, DispatchExtractorPy};
pub use dispatch_table::DispatchTableLocator;
pub use handler_classifier::{HandlerClassification, HandlerClassifier};
pub use opcode_table::{Handler, OpcodeTable};
pub use pe_loader::{Bitness, PEBinary};
pub use version::{VersionDetector, VmpVersion};
pub use xor_key_analyzer::{XorKeyAnalyzer, XorKeyEntry};

/// Main VMP Devirtualizer
pub struct VmpDevirtualizer {
    binary: PEBinary,
    version: VmpVersion,
    version_confidence: u8,
    opcode_table: OpcodeTable,
    dispatch_table_va: Option<u64>,
    handler_classifications: Vec<HandlerClassification>,
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

        let (version, version_confidence) = VersionDetector::detect(&binary).context("Failed to detect VMP version")?;

        let mut opcode_table = OpcodeTable::new();
        let mut dispatch_table_va = None;
        let mut handler_classifications = Vec::new();

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
                                match HandlerClassifier::classify_all(&binary, &handlers) {
                                    Ok(classifications) => {
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
                log::warn!("Failed to locate dispatch table: {}", e);
            }
        }

        Ok(VmpDevirtualizer {
            binary,
            version,
            version_confidence,
            opcode_table,
            dispatch_table_va,
            handler_classifications,
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

    /// Decode instruction at VIP address
    pub fn decode_instruction(&self, vip: u64) -> Result<DecodedInstruction> {
        let bytecode = Bytecode::from_vip(&self.binary, vip)?;
        let opcode_slot = bytecode.opcode_byte();

        let handler = self
            .opcode_table
            .lookup(opcode_slot)
            .context(format!("Unknown opcode: 0x{:02x}", opcode_slot))?;

        let operands = bytecode.decode_operands(&handler)?;
        let size = bytecode.size(&handler)?;

        Ok(DecodedInstruction {
            vip,
            opcode: opcode_slot,
            handler,
            operands,
            size,
        })
    }

    /// Devirtualize instruction range
    pub fn devirtualize_range(&self, start_vip: u64, end_vip: u64) -> Result<Vec<DecodedInstruction>> {
        let mut instructions = Vec::new();
        let mut vip = start_vip;

        while vip < end_vip {
            match self.decode_instruction(vip) {
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

        Ok(instructions)
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_detection() {
        // Stub: requires a real PE fixture. See AUDIT_REPORT.md Q13.
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
}
