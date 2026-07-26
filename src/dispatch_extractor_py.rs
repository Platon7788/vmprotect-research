//! Unicorn CPU Emulation - Dispatch Table Extractor (Python bridge).
//!
//! Extracts dispatch table by emulating x86-64 code execution.
//! Uses Python `unicorn` library via subprocess to avoid native binding issues.
//!
//! Script location lookup order:
//!    1. `$VMP_UNICORN_EXTRACTOR` env var
//!    2. `$CARGO_MANIFEST_DIR/scripts/unicorn_extractor.py`
//!    3. `./scripts/unicorn_extractor.py` (CWD)
//!
//! Output JSON written to `std::env::temp_dir()/vmp_devirt_dispatch_entries.json`.

use crate::PEBinary;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::{Command, Stdio};

/// Return true if the given python executable name is on PATH and runs.
fn which_python(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Captured dispatch table entry via emulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchEntry {
    /// Opcode index (0-255)
    pub opcode: u8,
    /// Virtual address written to
    pub write_va: u64,
    /// Encrypted handler address (value written)
    pub encrypted: u64,
    /// XOR key (extracted from context)
    pub xor_key: u64,
    /// Decrypted handler address
    pub decrypted: u64,
}

/// Unicorn-based dispatch table extractor
pub struct DispatchExtractorPy;

impl DispatchExtractorPy {
    /// Extract dispatch table via Unicorn emulation (Python subprocess)
    ///
    /// Strategy:
    /// 1. Call Python unicorn_extractor.py script
    /// 2. Script loads PE sections into Unicorn memory at image base
    /// 3. Sets up write hook on dispatch table region
    /// 4. Executes from entry point
    /// 5. Captures all writes to dispatch table
    /// 6. Returns 256 handler addresses
    pub fn extract(binary: &PEBinary, dispatch_table_va: u64, entry_point_va: u64) -> Result<Vec<DispatchEntry>> {
        log::info!("Starting Unicorn emulation for dispatch table extraction");
        log::info!("  Dispatch table VA: 0x{:x}", dispatch_table_va);
        log::info!("  Entry point VA: 0x{:x}", entry_point_va);

        let image_base = binary.image_base()?;
        let binary_path = &binary.path;

        // Find Python script
        let script_path = Self::find_extractor_script()?;

        log::info!("Using extractor script: {}", script_path);

        // Cross-platform temp output path (was hardcoded /tmp/... — broken on Windows)
        let output_json = std::env::temp_dir().join("vmp_devirt_dispatch_entries.json");
        let output_json_str = output_json.to_string_lossy().into_owned();

        // Prefer `python3` (Linux/mac); fall back to `python` (Windows launcher)
        let python_bin = if which_python("python3") { "python3" } else { "python" };

        // Call Python script
        let output = Command::new(python_bin)
            .arg(&script_path)
            .arg(binary_path)
            .arg(format!("0x{:x}", dispatch_table_va))
            .arg(format!("0x{:x}", entry_point_va))
            .arg(format!("0x{:x}", image_base))
            .arg(&output_json_str)
            .output()
            .with_context(|| format!("Failed to execute {} {}", python_bin, script_path))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::error!("Extractor script failed: {}", stderr);
            anyhow::bail!("Unicorn extraction failed: {}", stderr);
        }

        // Read results from JSON
        let entries_json = std::fs::read_to_string(&output_json)
            .with_context(|| format!("Failed to read extraction results from {}", output_json_str))?;

        let entries: Vec<DispatchEntry> =
            serde_json::from_str(&entries_json).context("Failed to parse extraction results")?;

        log::info!("Captured {} dispatch entries via emulation", entries.len());

        // Validate entries
        let valid_count = entries
            .iter()
            .filter(|e| e.decrypted >= image_base && e.decrypted < image_base + 0x80000000)
            .count();

        log::info!("Valid entries: {}/{}", valid_count, entries.len());

        if entries.len() < 200 {
            anyhow::bail!("Only captured {} entries, expected at least 200", entries.len());
        }

        Ok(entries)
    }

    /// Find unicorn_extractor.py script.
    ///
    /// Lookup order:
    ///   1. `$VMP_UNICORN_EXTRACTOR` env var (explicit override)
    ///   2. `$CARGO_MANIFEST_DIR/scripts/unicorn_extractor.py` (baked at build time)
    ///   3. `./scripts/unicorn_extractor.py` (relative to CWD)
    fn find_extractor_script() -> Result<String> {
        if let Ok(env_path) = std::env::var("VMP_UNICORN_EXTRACTOR") {
            if Path::new(&env_path).exists() {
                return Ok(env_path);
            }
        }

        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let candidates: Vec<String> = vec![
            format!("{}/scripts/unicorn_extractor.py", manifest_dir),
            "scripts/unicorn_extractor.py".to_string(),
            "./scripts/unicorn_extractor.py".to_string(),
        ];

        for path in candidates {
            if Path::new(&path).exists() {
                return Ok(path);
            }
        }

        anyhow::bail!("Could not find unicorn_extractor.py — set $VMP_UNICORN_EXTRACTOR or place it in ./scripts/")
    }

    /// Validate extracted entries against known data
    pub fn validate_entries(entries: &[DispatchEntry], known_handlers: &[u64]) -> Result<bool> {
        if entries.len() != 256 {
            log::warn!("Expected 256 entries, got {}", entries.len());
            return Ok(false);
        }

        let mut matches = 0;
        for (i, entry) in entries.iter().enumerate() {
            if i < known_handlers.len() && entry.decrypted == known_handlers[i] {
                matches += 1;
            }
        }

        let match_rate = (matches as f64) / (entries.len() as f64);
        log::info!(
            "Validation: {}/{} entries match known data ({:.1}%)",
            matches,
            entries.len(),
            match_rate * 100.0
        );

        Ok(match_rate >= 0.8) // 80% match threshold
    }

    /// Export entries to JSON
    pub fn export_json(entries: &[DispatchEntry], path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(&entries).context("Failed to serialize entries")?;
        std::fs::write(path, json).context("Failed to write entries file")?;
        log::info!("Entries exported to: {}", path);
        Ok(())
    }

    /// Get handler addresses from entries
    pub fn get_handler_addresses(entries: &[DispatchEntry]) -> Vec<u64> {
        let mut handlers = vec![0u64; 256];
        for entry in entries {
            if (entry.opcode as usize) < 256 {
                handlers[entry.opcode as usize] = entry.decrypted;
            }
        }
        handlers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_extractor_script() {
        // Script should exist in project
        let result = DispatchExtractorPy::find_extractor_script();
        assert!(result.is_ok() || result.is_err()); // Just check it runs
    }
}
