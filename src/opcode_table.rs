//! Opcode Dispatch Table
//!
//! Maps opcode slot bytes to handler information.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Handler information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handler {
    /// Handler name
    pub name: String,
    /// Opcode slot byte
    pub opcode: u8,
    /// Typical size in bytes
    pub size_bytes: Option<usize>,
}

/// Opcode dispatch table
pub struct OpcodeTable {
    table: HashMap<u8, Handler>,
}

impl OpcodeTable {
    /// Create new opcode table
    pub fn new() -> Self {
        OpcodeTable { table: HashMap::new() }
    }

    /// Register opcode → handler mapping
    pub fn register(&mut self, opcode: u8, handler: Handler) {
        self.table.insert(opcode, handler);
    }

    /// Lookup handler by opcode slot byte
    pub fn lookup(&self, opcode: u8) -> Option<Handler> {
        self.table.get(&opcode).cloned()
    }

    /// Get all registered opcodes
    pub fn opcodes(&self) -> Vec<u8> {
        let mut opcodes: Vec<_> = self.table.keys().copied().collect();
        opcodes.sort();
        opcodes
    }

    /// Get table size
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Load from JSON file.
    ///
    /// Accepts opcode_byte values either as `"0xNN"` (with prefix) or bare
    /// `"NN"` hex. A missing/short/malformed string produces a clear error
    /// via [`crate::parse_hex_rva`] rather than panicking on slice bounds.
    pub fn from_json(path: &str) -> anyhow::Result<Self> {
        use anyhow::Context;

        let data = std::fs::read_to_string(path)?;
        let entries: Vec<TraceEntry> = serde_json::from_str(&data)?;

        let mut table = OpcodeTable::new();
        for entry in entries {
            let opcode_u64 = crate::parse_hex_rva(&entry.opcode_byte)
                .with_context(|| format!("Invalid opcode_byte in JSON: {:?}", entry.opcode_byte))?;
            let opcode =
                u8::try_from(opcode_u64).with_context(|| format!("opcode_byte out of u8 range: 0x{:x}", opcode_u64))?;
            table.register(
                opcode,
                Handler {
                    name: entry.handler,
                    opcode,
                    size_bytes: Some(entry.size_bytes),
                },
            );
        }

        Ok(table)
    }

    /// Save to JSON file
    pub fn to_json(&self, path: &str) -> anyhow::Result<()> {
        let entries: Vec<_> = self
            .table
            .values()
            .map(|h| TraceEntry {
                opcode_byte: format!("0x{:02x}", h.opcode),
                handler: h.name.clone(),
                size_bytes: h.size_bytes.unwrap_or(5),
            })
            .collect();

        let json = serde_json::to_string_pretty(&entries)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

impl Default for OpcodeTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Trace entry (for JSON serialization)
#[derive(Debug, Serialize, Deserialize)]
struct TraceEntry {
    opcode_byte: String,
    handler: String,
    size_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_table() {
        let mut table = OpcodeTable::new();

        table.register(
            0x11,
            Handler {
                name: "PUSH_REG".to_string(),
                opcode: 0x11,
                size_bytes: Some(5),
            },
        );

        assert_eq!(table.len(), 1);
        assert!(table.lookup(0x11).is_some());
        assert!(table.lookup(0x22).is_none());
    }

    /// Regression: `from_json` used to slice `opcode_byte[2..]`
    /// unconditionally, panicking with `byte index 2 out of bounds`
    /// on any string shorter than two characters. It must now return
    /// `Err`, so a caller of the public loader can recover.
    #[test]
    fn from_json_short_opcode_byte_errors_instead_of_panicking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.json");
        std::fs::write(&path, r#"[{"opcode_byte":"","handler":"X","size_bytes":1}]"#).unwrap();

        let result = OpcodeTable::from_json(path.to_str().unwrap());
        assert!(result.is_err(), "empty opcode_byte must not panic");
    }

    /// `from_json` should accept bare hex (no `0x` prefix) — this used to
    /// silently succeed only for well-formed prefixed strings and slice-
    /// panic for anything unusual.
    #[test]
    fn from_json_accepts_bare_hex_opcode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bare.json");
        std::fs::write(&path, r#"[{"opcode_byte":"1a","handler":"X","size_bytes":2}]"#).unwrap();

        let table = OpcodeTable::from_json(path.to_str().unwrap()).expect("bare hex must parse");
        assert_eq!(table.len(), 1);
        assert!(table.lookup(0x1a).is_some());
    }
}
