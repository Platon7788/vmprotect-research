//! Handler Classifier
//!
//! Classifies VMP handlers by analyzing their bytecode patterns.

use crate::handler_semantic::{SemanticMatcher, VmpSemantic};
use crate::{Bitness, PEBinary};
use anyhow::Result;
use std::collections::HashMap;

/// Handler classification result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HandlerClassification {
    /// Handler virtual address
    pub va: u64,
    /// Classified handler type
    pub handler_type: String,
    /// Estimated size in bytes
    pub size: usize,
    /// Confidence score (0-100)
    pub confidence: u8,
    /// VMP-semantic category recognised in the handler body, if any.
    ///
    /// Add-only field: `None` means the semantic matcher did not
    /// recognise a fingerprint; consumers should fall back on
    /// [`Self::handler_type`] as before. See
    /// [`crate::handler_semantic`] for the matcher and enum.
    #[serde(default)]
    pub vmp_semantic: Option<VmpSemantic>,
}

/// Handler classifier
pub struct HandlerClassifier;

impl HandlerClassifier {
    /// Classify a single handler by analyzing its bytecode
    pub fn classify(binary: &PEBinary, handler_va: u64) -> Result<HandlerClassification> {
        if handler_va == 0 {
            return Ok(HandlerClassification {
                va: handler_va,
                handler_type: "INVALID".to_string(),
                size: 0,
                confidence: 0,
                vmp_semantic: None,
            });
        }

        let bitness = binary.bitness()?;

        // Read handler bytecode (typically 20-100 bytes; up to as many as
        // remain in the containing section, so a short handler near a
        // section boundary doesn't get wrongly reported as unreadable).
        let bytecode = match binary.read_bytes_up_to(handler_va, 100) {
            Ok(data) => data,
            Err(_) => {
                return Ok(HandlerClassification {
                    va: handler_va,
                    handler_type: "UNREADABLE".to_string(),
                    size: 0,
                    confidence: 0,
                    vmp_semantic: None,
                });
            }
        };

        // Analyze bytecode patterns (x86-instruction-level fallback).
        let (handler_type, size, confidence) = Self::analyze_bytecode(&bytecode, bitness);

        // VMP-level semantic classifier. Runs independently of the x86
        // fallback so the two layers can disagree without either
        // silently masking the other -- consumers see both.
        let vmp_semantic = SemanticMatcher::classify(&bytecode, bitness);

        Ok(HandlerClassification {
            va: handler_va,
            handler_type,
            size,
            confidence,
            vmp_semantic,
        })
    }

    /// Analyze bytecode to determine handler type.
    ///
    /// `bitness` gates the REX-prefix branch (`0x48`): that branch only
    /// applies on x86-64 (`Bitness::X64`). On x86 (`Bitness::X86`), `0x48`
    /// is itself a complete one-byte instruction (`DEC EAX`), not a prefix,
    /// so treating it as REX and inspecting the following byte would
    /// misclassify the handler. All other single-byte / bare-opcode
    /// patterns below (`0x89`, `0x8B`, `0x01`, `0x29`, `0x31`, `0x21`,
    /// `0x09`, `PUSH`, `POP`, `RET`, `JMP`, `FF`, `C7`, `MOV_REG_IMM`) are
    /// identical encodings on both bitnesses and apply unconditionally.
    fn analyze_bytecode(bytecode: &[u8], bitness: Bitness) -> (String, usize, u8) {
        if bytecode.is_empty() {
            return ("EMPTY".to_string(), 0, 0);
        }

        // Pattern matching for common VMP handlers
        // These are simplified patterns - real implementation would be more sophisticated

        let mut handler_type = "UNKNOWN".to_string();
        let mut confidence = 50u8;
        let mut size = 5usize;

        // Check for common instruction patterns
        match bytecode[0] {
            // x86-64 REX prefix (64-bit operations) — only valid as a prefix on x64.
            0x48 if bitness == Bitness::X64 => {
                if bytecode.len() > 1 {
                    match bytecode[1] {
                        0x89 => {
                            handler_type = "MOV_REG_REG".to_string();
                            confidence = 85;
                            size = 3;
                        }
                        0x8B => {
                            handler_type = "MOV_REG_MEM".to_string();
                            confidence = 85;
                            size = 4;
                        }
                        0x01 => {
                            handler_type = "ADD_REG_REG".to_string();
                            confidence = 80;
                            size = 3;
                        }
                        0x29 => {
                            handler_type = "SUB_REG_REG".to_string();
                            confidence = 80;
                            size = 3;
                        }
                        0x31 => {
                            handler_type = "XOR_REG_REG".to_string();
                            confidence = 80;
                            size = 3;
                        }
                        0x21 => {
                            handler_type = "AND_REG_REG".to_string();
                            confidence = 80;
                            size = 3;
                        }
                        0x09 => {
                            handler_type = "OR_REG_REG".to_string();
                            confidence = 80;
                            size = 3;
                        }
                        _ => {
                            handler_type = "REX_PREFIX".to_string();
                            confidence = 40;
                        }
                    }
                }
            }
            0x89 => {
                handler_type = "MOV_REG_REG".to_string();
                confidence = 85;
                size = 2;
            }
            0x8B => {
                handler_type = "MOV_REG_MEM".to_string();
                confidence = 85;
                size = 3;
            }
            0x01 => {
                handler_type = "ADD_REG_REG".to_string();
                confidence = 80;
                size = 2;
            }
            0x29 => {
                handler_type = "SUB_REG_REG".to_string();
                confidence = 80;
                size = 2;
            }
            0x31 => {
                handler_type = "XOR_REG_REG".to_string();
                confidence = 80;
                size = 2;
            }
            0x21 => {
                handler_type = "AND_REG_REG".to_string();
                confidence = 80;
                size = 2;
            }
            0x09 => {
                handler_type = "OR_REG_REG".to_string();
                confidence = 80;
                size = 2;
            }
            0x50..=0x57 => {
                handler_type = "PUSH_REG".to_string();
                confidence = 90;
                size = 1;
            }
            0x58..=0x5F => {
                handler_type = "POP_REG".to_string();
                confidence = 90;
                size = 1;
            }
            0xC3 => {
                handler_type = "RET".to_string();
                confidence = 95;
                size = 1;
            }
            0xE9 => {
                handler_type = "JMP".to_string();
                confidence = 90;
                size = 5;
            }
            0xFF => {
                if bytecode.len() > 1 {
                    match bytecode[1] & 0x38 {
                        0x00 => {
                            handler_type = "INC_REG".to_string();
                            confidence = 85;
                            size = 2;
                        }
                        0x08 => {
                            handler_type = "DEC_REG".to_string();
                            confidence = 85;
                            size = 2;
                        }
                        0x20 => {
                            handler_type = "JMP_REG".to_string();
                            confidence = 85;
                            size = 2;
                        }
                        0x30 => {
                            handler_type = "CALL_REG".to_string();
                            confidence = 85;
                            size = 2;
                        }
                        _ => {
                            handler_type = "FF_PREFIX".to_string();
                            confidence = 40;
                        }
                    }
                }
            }
            0xC7 => {
                handler_type = "MOV_REG_IMM".to_string();
                confidence = 80;
                size = 7;
            }
            0xB8..=0xBF => {
                handler_type = "MOV_REG_IMM".to_string();
                confidence = 85;
                size = 5;
            }
            _ => {
                handler_type = "UNKNOWN".to_string();
                confidence = 30;
                size = 5;
            }
        }

        (handler_type, size, confidence)
    }

    /// Classify all handlers in a list
    pub fn classify_all(binary: &PEBinary, handlers: &[u64]) -> Result<Vec<HandlerClassification>> {
        let mut classifications = Vec::new();

        for &handler_va in handlers {
            match Self::classify(binary, handler_va) {
                Ok(classification) => classifications.push(classification),
                Err(_) => {
                    classifications.push(HandlerClassification {
                        va: handler_va,
                        handler_type: "ERROR".to_string(),
                        size: 0,
                        confidence: 0,
                        vmp_semantic: None,
                    });
                }
            }
        }

        Ok(classifications)
    }

    /// Get handler statistics
    pub fn get_statistics(classifications: &[HandlerClassification]) -> HashMap<String, usize> {
        let mut stats = HashMap::new();

        for classification in classifications {
            *stats.entry(classification.handler_type.clone()).or_insert(0) += 1;
        }

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Classify a synthetic handler body inside a real minimal PE so the
    /// full `classify` path (read_bytes_up_to + analyze_bytecode +
    /// SemanticMatcher) is exercised end-to-end. Replaces the empty stub.
    ///
    /// Commit G split the coarse `Pop` label: this canonical CTX-store
    /// body now lands on the tighter `Popreg` shape (single `disp8` in
    /// `[0, 0x80)`).
    #[test]
    fn classify_pop_shape_body_in_real_pe_yields_popreg_semantic() {
        use crate::pe_loader::test_util::build_minimal_pe;
        // MOV rax,[r14]; ADD r14,8; MOV [rbp+8],rax; JMP [rip]
        let handler_body = [
            0x49, 0x8B, 0x06, 0x49, 0x83, 0xC6, 0x08, 0x48, 0x89, 0x45, 0x08, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        ];
        let image_base = 0x1_4000_0000u64;
        let section_rva = 0x1000u32;
        let binary = build_minimal_pe(true, image_base, section_rva, &handler_body);
        let handler_va = image_base + section_rva as u64;

        let classification = HandlerClassifier::classify(&binary, handler_va).expect("classify");
        assert_eq!(classification.vmp_semantic, Some(VmpSemantic::Popreg));
        assert!(!classification.handler_type.is_empty());
    }

    #[test]
    fn x86_mov_reg_reg_classified_without_rex() {
        let (handler_type, size, confidence) = HandlerClassifier::analyze_bytecode(&[0x89, 0xD8], Bitness::X86);
        assert_eq!(handler_type, "MOV_REG_REG");
        assert_eq!(size, 2);
        assert_eq!(confidence, 85);
    }

    #[test]
    fn x86_add_reg_reg_classified_without_rex() {
        let (handler_type, size, confidence) = HandlerClassifier::analyze_bytecode(&[0x01, 0xC8], Bitness::X86);
        assert_eq!(handler_type, "ADD_REG_REG");
        assert_eq!(size, 2);
        assert_eq!(confidence, 80);
    }

    #[test]
    fn x86_xor_reg_reg_classified_without_rex() {
        let (handler_type, ..) = HandlerClassifier::analyze_bytecode(&[0x31, 0xC0], Bitness::X86);
        assert_eq!(handler_type, "XOR_REG_REG");
    }

    #[test]
    fn x86_does_not_treat_0x48_as_rex_prefix() {
        // On x86, 0x48 alone is a complete instruction (DEC EAX), not a REX
        // prefix. Followed by a byte that would look like a REX-prefixed
        // MOV_REG_REG opcode on x64, it must NOT be classified as such here.
        let (handler_type, ..) = HandlerClassifier::analyze_bytecode(&[0x48, 0x89], Bitness::X86);
        assert_ne!(handler_type, "MOV_REG_REG");
    }

    #[test]
    fn x64_rex_prefix_mov_reg_reg_still_works() {
        let (handler_type, size, confidence) = HandlerClassifier::analyze_bytecode(&[0x48, 0x89, 0xD8], Bitness::X64);
        assert_eq!(handler_type, "MOV_REG_REG");
        assert_eq!(size, 3);
        assert_eq!(confidence, 85);
    }

    #[test]
    fn shared_patterns_apply_to_both_bitnesses() {
        let (x86_type, ..) = HandlerClassifier::analyze_bytecode(&[0xC3], Bitness::X86);
        let (x64_type, ..) = HandlerClassifier::analyze_bytecode(&[0xC3], Bitness::X64);
        assert_eq!(x86_type, "RET");
        assert_eq!(x64_type, "RET");
    }

    // The following tests target the new `vmp_semantic` field wired
    // into `HandlerClassification`. Full pattern coverage lives in
    // `crate::handler_semantic::tests`; these tests only verify that
    // the field is exposed on the classification struct, that its
    // default is `None`, and that JSON serialisation round-trips.

    #[test]
    fn handler_classification_defaults_vmp_semantic_to_none() {
        let c = HandlerClassification {
            va: 0x1000,
            handler_type: "MOV_REG_REG".to_string(),
            size: 3,
            confidence: 85,
            vmp_semantic: None,
        };
        assert!(c.vmp_semantic.is_none());
    }

    #[test]
    fn handler_classification_serializes_vmp_semantic() {
        let c = HandlerClassification {
            va: 0x1000,
            handler_type: "MOV_REG_MEM".to_string(),
            size: 4,
            confidence: 85,
            vmp_semantic: Some(VmpSemantic::Pop),
        };
        let json = serde_json::to_string(&c).expect("serialize");
        assert!(json.contains("\"vmp_semantic\":\"Pop\""));
        let back: HandlerClassification = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.vmp_semantic, Some(VmpSemantic::Pop));
    }

    #[test]
    fn handler_classification_deserializes_without_field_for_backcompat() {
        // Older JSON blobs (produced before Q2) will not contain the
        // new field. `#[serde(default)]` on the struct field must let
        // them round-trip into `None` rather than fail hard.
        let older_json = r#"{"va":4096,"handler_type":"MOV_REG_REG","size":3,"confidence":85}"#;
        let c: HandlerClassification = serde_json::from_str(older_json).expect("deserialize");
        assert!(c.vmp_semantic.is_none());
    }
}
