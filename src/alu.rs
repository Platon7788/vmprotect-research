//! ALU Reconstruction
//!
//! Reconstructs arithmetic operations from NOR/NAND chains.

use std::collections::HashMap;

/// ALU operation types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ALUOp {
    /// Addition
    Add,
    /// Subtraction
    Sub,
    /// XOR
    Xor,
    /// OR
    Or,
    /// AND
    And,
    /// NOT
    Not,
    /// Shift left
    Shl,
    /// Shift right
    Shr,
}

/// ALU chain reconstructor
pub struct ALUReconstructor {
    patterns: HashMap<Vec<String>, ALUOp>,
}

impl ALUReconstructor {
    /// Create new ALU reconstructor
    pub fn new() -> Self {
        let mut patterns = HashMap::new();

        // NOR truth table: NOR(a,b) = !(a | b)
        // NAND truth table: NAND(a,b) = !(a & b)

        // Pattern: 4x NOR → ADD (De Morgan's law composition)
        patterns.insert(vec!["NOR".to_string(); 4], ALUOp::Add);

        // Pattern: 2x NAND → AND (De Morgan's law)
        patterns.insert(vec!["NAND".to_string(), "NAND".to_string()], ALUOp::And);

        // Pattern: Single NOR → NOT
        patterns.insert(vec!["NOR".to_string()], ALUOp::Not);

        // Pattern: 3x NOR → SUB
        patterns.insert(vec!["NOR".to_string(); 3], ALUOp::Sub);

        ALUReconstructor { patterns }
    }

    /// Match chain of operations to ALU type
    pub fn match_chain(&self, chain: &[String]) -> Option<ALUOp> {
        self.patterns.get(chain).cloned()
    }

    /// Decompose NOR/NAND chain to operands and operation.
    ///
    /// The two operands are named after the VM-stack slots VMP's ALU chains
    /// consume from: the top two entries of the VM stack (VSP-relative).
    /// Slot names are hardcoded to the x64 convention (`vsp+0`, `vsp+8`,
    /// 8-byte slots); a bitness-aware variant (x86 uses 4-byte slots, i.e.
    /// `vsp+0`/`vsp+4`) is left as future work — see AUDIT_REPORT.md Q3.
    pub fn decompose_chain(&self, chain: &[String]) -> Option<(String, String, ALUOp)> {
        if chain.len() >= 2 {
            let op1 = "vsp+0".to_string();
            let op2 = "vsp+8".to_string();
            let alu_op = self.match_chain(chain)?;
            Some((op1, op2, alu_op))
        } else {
            None
        }
    }

    /// Check if sequence is valid NOR/NAND chain
    pub fn is_valid_chain(chain: &[String]) -> bool {
        chain.iter().all(|op| op == "NOR" || op == "NAND")
    }
}

impl Default for ALUReconstructor {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan a decoded-instruction slice for consecutive runs of NOR/NAND chain
/// handlers and stamp the reconstructed `ALUOp` onto the last instruction
/// of each run.
///
/// Lives here (rather than in `lib.rs`) so all knowledge of what a chain
/// *is* — the handler-name constants, the `ALUReconstructor` pattern
/// table — sits in one file. Runs are grouped by identical handler
/// name, so a run is always homogeneous (all `H_NOR_CHAIN` or all
/// `H_NAND_CHAIN`); the reconstructor only recognises homogeneous
/// chains, so mixed runs are never produced here.
///
/// Kept as a free function (not a method on `VmpDevirtualizer`) so it
/// can be unit tested directly on synthetic `DecodedInstruction`
/// slices — no PE fixture needed.
pub fn reconstruct_alu_chains(instructions: &mut [crate::DecodedInstruction], reconstructor: &ALUReconstructor) {
    use crate::bytecode::{H_NAND_CHAIN, H_NOR_CHAIN};

    let mut i = 0;
    while i < instructions.len() {
        let handler_name = instructions[i].handler.name.clone();
        let op_str = if handler_name == H_NOR_CHAIN {
            "NOR"
        } else if handler_name == H_NAND_CHAIN {
            "NAND"
        } else {
            i += 1;
            continue;
        };

        let mut j = i + 1;
        while j < instructions.len() && instructions[j].handler.name == handler_name {
            j += 1;
        }

        let chain_len = j - i;
        let chain = vec![op_str.to_string(); chain_len];

        // Use `match_chain` (not `decompose_chain`) so all chain lengths
        // registered in `patterns` — including the single-NOR -> Not
        // entry — resolve. `decompose_chain` gates on `len >= 2` to
        // keep its two-operand return type meaningful, but we only
        // need the ALUOp here; operand names live on the chain
        // handlers themselves.
        if let Some(alu_op) = reconstructor.match_chain(&chain) {
            let last_idx = j - 1;
            log::debug!(
                "Reconstructed {}x {} at 0x{:x} -> {:?}",
                chain_len,
                op_str,
                instructions[last_idx].vip,
                alu_op
            );
            instructions[last_idx].alu_op = Some(alu_op);
        }

        i = j;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DecodedInstruction, Handler};

    #[test]
    fn test_pattern_matching() {
        let reconstructor = ALUReconstructor::new();

        let chain = vec!["NOR".to_string(); 4];
        let op = reconstructor.match_chain(&chain);

        assert_eq!(op, Some(ALUOp::Add));
    }

    #[test]
    fn test_nor_not() {
        let reconstructor = ALUReconstructor::new();

        let chain = vec!["NOR".to_string()];
        let op = reconstructor.match_chain(&chain);

        assert_eq!(op, Some(ALUOp::Not));
    }

    #[test]
    fn test_nand_and() {
        let reconstructor = ALUReconstructor::new();

        let chain = vec!["NAND".to_string(), "NAND".to_string()];
        let op = reconstructor.match_chain(&chain);

        assert_eq!(op, Some(ALUOp::And));
    }

    #[test]
    fn test_decompose_chain_uses_vsp_slot_names() {
        let reconstructor = ALUReconstructor::new();

        let chain = vec!["NOR".to_string(); 4];
        let result = reconstructor.decompose_chain(&chain);

        assert_eq!(result, Some(("vsp+0".to_string(), "vsp+8".to_string(), ALUOp::Add)));
    }

    fn make_instr(vip: u64, handler_name: &str) -> DecodedInstruction {
        DecodedInstruction {
            vip,
            opcode: 0,
            handler: Handler {
                name: handler_name.to_string(),
                opcode: 0,
                size_bytes: None,
            },
            operands: Vec::new(),
            size: 1,
            alu_op: None,
        }
    }

    #[test]
    fn reconstruct_alu_chains_stamps_last_instruction_of_nor_run() {
        let reconstructor = ALUReconstructor::new();
        let mut instructions = vec![
            make_instr(0x1000, "NOR_CHAIN"),
            make_instr(0x1001, "NOR_CHAIN"),
            make_instr(0x1002, "NOR_CHAIN"),
            make_instr(0x1003, "NOR_CHAIN"),
        ];

        reconstruct_alu_chains(&mut instructions, &reconstructor);

        assert_eq!(instructions[0].alu_op, None);
        assert_eq!(instructions[1].alu_op, None);
        assert_eq!(instructions[2].alu_op, None);
        assert_eq!(instructions[3].alu_op, Some(ALUOp::Add));
    }

    #[test]
    fn reconstruct_alu_chains_ignores_non_chain_handlers() {
        let reconstructor = ALUReconstructor::new();
        let mut instructions = vec![make_instr(0x1000, "PUSH_REG"), make_instr(0x1001, "RET")];

        reconstruct_alu_chains(&mut instructions, &reconstructor);

        assert!(instructions.iter().all(|i| i.alu_op.is_none()));
    }

    /// Regression: `patterns` registers a single-`NOR` entry -> `Not`, but
    /// the earlier implementation routed chains through `decompose_chain`,
    /// which gates on `chain.len() >= 2` and returned `None` here — so a
    /// lone `NOR_CHAIN` handler was silently dropped.
    #[test]
    fn reconstruct_alu_chains_stamps_lone_nor_as_not() {
        let reconstructor = ALUReconstructor::new();
        let mut instructions = vec![
            make_instr(0x1000, "PUSH_REG"),
            make_instr(0x1001, "NOR_CHAIN"),
            make_instr(0x1002, "PUSH_REG"),
        ];

        reconstruct_alu_chains(&mut instructions, &reconstructor);

        assert_eq!(instructions[0].alu_op, None);
        assert_eq!(instructions[1].alu_op, Some(ALUOp::Not));
        assert_eq!(instructions[2].alu_op, None);
    }

    #[test]
    fn reconstruct_alu_chains_handles_separate_runs_independently() {
        let reconstructor = ALUReconstructor::new();
        let mut instructions = vec![
            make_instr(0x1000, "NAND_CHAIN"),
            make_instr(0x1001, "NAND_CHAIN"),
            make_instr(0x1002, "PUSH_REG"),
            make_instr(0x1003, "NOR_CHAIN"),
            make_instr(0x1004, "NOR_CHAIN"),
            make_instr(0x1005, "NOR_CHAIN"),
            make_instr(0x1006, "NOR_CHAIN"),
        ];

        reconstruct_alu_chains(&mut instructions, &reconstructor);

        assert_eq!(instructions[0].alu_op, None);
        assert_eq!(instructions[1].alu_op, Some(ALUOp::And));
        assert_eq!(instructions[2].alu_op, None);
        assert_eq!(instructions[6].alu_op, Some(ALUOp::Add));
    }
}
