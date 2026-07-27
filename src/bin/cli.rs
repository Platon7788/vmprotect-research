//! VMP Devirtualizer CLI Tool
//!
//! Command-line interface for devirtualizing VMP-protected binaries.

use anyhow::Context;
use clap::{Parser, ValueEnum};
use log::info;
use std::path::PathBuf;
use std::process::ExitCode;
use vmp_devirt::{parse_hex_rva, VmpDevirtualizer, VmpVersion};

/// Exit code for the "not a VMP-protected binary" case (F2).
///
/// Distinguished from 1 (generic anyhow error) so scripts and CI can
/// branch on "unsupported input" without inspecting stderr.
const EXIT_NOT_VMP: u8 = 2;

/// Version override values accepted by `--force-version`.
#[derive(Debug, Clone, Copy, ValueEnum)]
#[value(rename_all = "lower")]
enum ForceVersion {
    /// VMProtect 1.x
    Vmp1,
    /// VMProtect 2.x
    Vmp2,
    /// VMProtect 3.0-3.4
    Vmp30,
    /// VMProtect 3.5.0-3.5.1
    Vmp35,
    /// VMProtect 3.6-3.10.5
    Vmp36,
}

impl From<ForceVersion> for VmpVersion {
    fn from(value: ForceVersion) -> Self {
        match value {
            ForceVersion::Vmp1 => VmpVersion::Vmp1,
            ForceVersion::Vmp2 => VmpVersion::Vmp2,
            ForceVersion::Vmp30 => VmpVersion::Vmp30,
            ForceVersion::Vmp35 => VmpVersion::Vmp35,
            ForceVersion::Vmp36 => VmpVersion::Vmp36Plus,
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "vmp_devirt")]
#[command(about = "VMProtect Devirtualizer (VMP 1.0-3.10.5)", long_about = None)]
struct Args {
    /// Path to VMP-protected binary
    #[arg(value_name = "BINARY")]
    binary: PathBuf,

    /// VIP address to start devirtualization (hex). Defaults to the PE
    /// entry point when omitted.
    #[arg(short = 'i', long, value_name = "ADDRESS")]
    vip: Option<String>,

    /// Output format (json, text)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Output file (default: stdout)
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Export opcode table to JSON
    #[arg(long, value_name = "FILE")]
    export_opcodes: Option<PathBuf>,

    /// Export handler classifications to JSON
    #[arg(long, value_name = "FILE")]
    export_handlers: Option<PathBuf>,

    /// Optional dispatch-table RVA hint (hex, e.g. 0x12340). If omitted or
    /// invalid, the tool scans candidate sections.
    #[arg(long, value_name = "RVA")]
    dispatch_rva: Option<String>,

    /// Force a specific VMP version, bypassing the detector. Research
    /// override; combine with `--dispatch-rva` when the detector cannot
    /// locate the dispatch table on its own.
    #[arg(long, value_name = "VERSION", value_enum)]
    force_version: Option<ForceVersion>,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> anyhow::Result<ExitCode> {
    let args = Args::parse();

    // Initialize logging
    if args.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    info!("VMP Devirtualizer v0.1.0");
    info!("Loading binary: {}", args.binary.display());

    // Parse the optional dispatch-table RVA hint, if provided.
    let dispatch_rva_hint = match args.dispatch_rva.as_deref() {
        Some(rva_str) => {
            Some(parse_hex_rva(rva_str).with_context(|| format!("Invalid --dispatch-rva value: {}", rva_str))?)
        }
        None => None,
    };

    // Load binary and detect version
    let mut devirt = VmpDevirtualizer::new_with_hint(&args.binary, dispatch_rva_hint)?;

    // F3: apply --force-version override before we log or gate on version.
    if let Some(forced) = args.force_version {
        let forced_version: VmpVersion = forced.into();
        info!(
            "Version detector overridden by --force-version: {} (detector said {}/{})",
            forced_version.as_str(),
            devirt.version().as_str(),
            devirt.version_confidence()
        );
        devirt.force_version(forced_version);
    }

    let version = devirt.version();
    info!("Detected VMP version: {}", version.as_str());
    info!("Version detection confidence: {}/100", devirt.version_confidence());

    // Display dispatch table info
    if let Some(dt_va) = devirt.dispatch_table_va() {
        info!("Dispatch table VA: 0x{:x}", dt_va);
        info!("Handlers extracted: {}", devirt.handler_classifications().len());

        // Display handler statistics
        let stats = devirt.handler_statistics();
        info!("Handler types found: {}", stats.len());

        let mut sorted_stats: Vec<_> = stats.iter().collect();
        sorted_stats.sort_by(|a, b| b.1.cmp(a.1));

        info!("Top 10 handler types:");
        for (i, (handler_type, count)) in sorted_stats.iter().take(10).enumerate() {
            info!("  {}. {} ({})", i + 1, handler_type, count);
        }
    } else {
        info!("Could not locate dispatch table");
    }

    // Export opcode table if requested
    if let Some(export_path) = args.export_opcodes {
        devirt.export_opcode_table(&export_path.to_string_lossy())?;
    }

    // Export handler classifications if requested
    if let Some(export_path) = args.export_handlers {
        devirt.export_handler_classifications(&export_path.to_string_lossy())?;
    }

    // F2: refuse to devirtualize a binary that shows no signs of being VMP
    // and provides no dispatch table. --force-version defeats the version
    // check; --dispatch-rva defeats the dispatch-table check. Both together
    // are the intended escape hatch for researchers analyzing edge cases.
    // The predicate itself lives on VmpDevirtualizer so wrappers can reuse it.
    if !devirt.looks_like_vmp() {
        eprintln!(
            "error: {} does not appear to be a VMP-protected binary.",
            args.binary.display()
        );
        eprintln!(
            "       (version=Unknown, confidence={}/100, no dispatch table located)",
            devirt.version_confidence()
        );
        eprintln!("       Use --force-version and/or --dispatch-rva to override for research.");
        return Ok(ExitCode::from(EXIT_NOT_VMP));
    }

    // F1: default VIP to the PE entry point rather than a hardcoded VA. The
    // old default (0x140001000) worked only for /LARGEADDRESSAWARE x64 images
    // whose first code section happened to land there.
    let vip = match args.vip.as_deref() {
        Some(vip_str) => parse_hex_rva(vip_str).with_context(|| format!("Invalid --vip value: {}", vip_str))?,
        None => devirt
            .binary()
            .entry_point_va()
            .context("--vip omitted and PE has no resolvable entry point")?,
    };

    info!("Starting devirtualization at VIP: 0x{:x}", vip);

    // Decode instructions
    let instructions = devirt.devirtualize_range(vip, vip + 0x1000)?;

    info!("Decoded {} instructions", instructions.len());

    // Format output
    let output = match args.format.as_str() {
        "json" => format_json(&instructions)?,
        "text" => format_text(&instructions),
        _ => anyhow::bail!("Unknown format: {}", args.format),
    };

    // Write output
    if let Some(output_path) = args.output {
        std::fs::write(&output_path, &output)?;
        info!("Output written to: {}", output_path.display());
    } else {
        println!("{}", output);
    }

    Ok(ExitCode::SUCCESS)
}

/// Format instructions as JSON
fn format_json(instructions: &[vmp_devirt::DecodedInstruction]) -> anyhow::Result<String> {
    let json_instructions: Vec<_> = instructions
        .iter()
        .map(|instr| {
            serde_json::json!({
                "vip": format!("0x{:x}", instr.vip),
                "opcode": format!("0x{:02x}", instr.opcode),
                "handler": instr.handler.name,
                "operands": instr.operands.iter().map(|o| format!("0x{:x}", o)).collect::<Vec<_>>(),
                "size": instr.size,
            })
        })
        .collect();

    Ok(serde_json::to_string_pretty(&json_instructions)?)
}

/// Format instructions as text
fn format_text(instructions: &[vmp_devirt::DecodedInstruction]) -> String {
    let mut output = String::new();
    output.push_str("VIP Address | Opcode | Handler          | Size | Operands\n");
    output.push_str("------------|--------|------------------|------|----------\n");

    for instr in instructions {
        let operands = instr
            .operands
            .iter()
            .map(|o| format!("0x{:x}", o))
            .collect::<Vec<_>>()
            .join(", ");

        output.push_str(&format!(
            "0x{:08x}  | 0x{:02x}   | {:<16} | {:>4} | {}\n",
            instr.vip, instr.opcode, instr.handler.name, instr.size, operands
        ));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// Guards against short-flag / long-flag collisions and other clap
    /// definition mistakes at CI time. Without this, mistakes only surface
    /// the first time the binary is actually invoked.
    #[test]
    fn cli_definition_is_valid() {
        Args::command().debug_assert();
    }
}
