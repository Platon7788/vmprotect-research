//! Integration tests for the `vmp_devirt` CLI binary.
//!
//! Guards Day-1 findings F1/F2/F3 and the pre-existing `-v/-i` flag
//! disambiguation. Each test builds a minimal PE fixture on disk and
//! invokes the compiled binary through `assert_cmd`.

use assert_cmd::Command;
use predicates::prelude::*;

mod common;

use common::write_minimal_pe;

/// F2: a plain PE with no VMP markers must exit with EXIT_NOT_VMP (2)
/// and print an actionable message on stderr.
#[test]
fn f2_non_vmp_binary_exits_with_code_2() {
    // Section data: a few NOPs — nothing that trips any version heuristic.
    let fixture = write_minimal_pe(0x1_4000_0000, 0x1000, &[0x90; 32]);

    Command::cargo_bin("vmp_devirt")
        .expect("cargo bin exists")
        .arg(fixture.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("does not appear to be a VMP-protected binary"))
        .stderr(predicate::str::contains("--force-version"));
}

/// F3 + F1: `--force-version` bypasses the version gate, and `--vip`
/// defaulting to the PE entry point means the run does not crash with
/// "Invalid VA" on a fixture whose entry lies at image_base+0x1000
/// rather than the old hardcoded 0x140001000.
///
/// Tightened to also match the CLI's "overridden by --force-version"
/// stderr log, so a regression where `devirt.force_version(...)` is
/// silently dropped (but the F2 gate happens to open some other way)
/// would still fail this test.
#[test]
fn f3_force_version_bypasses_non_vmp_gate() {
    let fixture = write_minimal_pe(0x1_4000_0000, 0x1000, &[0x90; 32]);

    Command::cargo_bin("vmp_devirt")
        .expect("cargo bin exists")
        .arg(fixture.path())
        .args(["--force-version", "vmp35"])
        .assert()
        .success()
        .stderr(predicate::str::contains("overridden by --force-version"))
        .stderr(predicate::str::contains("VMP 3.5.0-3.5.1"));
}

/// F3 rejects unknown version strings at CLI parse time (exit 2 per clap).
#[test]
fn f3_force_version_rejects_unknown_value() {
    let fixture = write_minimal_pe(0x1_4000_0000, 0x1000, &[0x90; 32]);

    Command::cargo_bin("vmp_devirt")
        .expect("cargo bin exists")
        .arg(fixture.path())
        .args(["--force-version", "vmp99"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value"));
}

/// Regression guard for the pre-existing `-v`/`-i` flag split:
/// `-i` is the short form of `--vip`, `-v` is the short form of
/// `--verbose`. A clap collision would flip these silently.
#[test]
fn short_flag_disambiguation_is_stable() {
    let fixture = write_minimal_pe(0x1_4000_0000, 0x1000, &[0x90; 32]);

    // -v alone (no --force-version) hits the F2 non-VMP path (exit 2),
    // and because -v enables debug logging, stderr contains the
    // detector's own "detected" log line.
    Command::cargo_bin("vmp_devirt")
        .expect("cargo bin exists")
        .arg(fixture.path())
        .arg("-v")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("does not appear to be a VMP-protected binary"));

    // -i takes a value (the VIP override). Passing an out-of-range VA
    // together with --force-version proves -i is the VIP short flag:
    // the value flows through to `devirtualize_range`, which logs
    // "Starting devirtualization at VIP: 0xdeadbeef" and then a
    // per-instruction "Invalid VA" warning. If `-i` had collided with
    // `-v` (or been rejected as unexpected) neither line would appear.
    Command::cargo_bin("vmp_devirt")
        .expect("cargo bin exists")
        .arg(fixture.path())
        .args(["--force-version", "vmp35", "-i", "0xdeadbeef"])
        .assert()
        .stderr(predicate::str::contains("Starting devirtualization at VIP: 0xdeadbeef"))
        .stderr(predicate::str::contains("Invalid VA: 0xdeadbeef"));
}

/// F1: with `--vip` omitted, the tool must default to the PE entry
/// point. If the old hardcoded default (0x140001000) were still in
/// place, this fixture — whose entry is at image_base+0x1000 =
/// 0x140001000 by coincidence — would pass by accident. So this
/// test uses a *different* image_base to make the coincidence
/// impossible: the old default lands outside every section and would
/// fail with "Invalid VA".
/// New in Commit E: when the ProtectorDetector identifies a specific
/// vendor we can't devirtualise (compressors, Themida-family, etc.),
/// the CLI must exit with `EXIT_UNSUPPORTED_FAMILY` (3) rather than
/// the "not VMP" code 2. The message must name the vendor and
/// point to `--force-version` as the research escape hatch.
///
/// We simulate a `UPX` detection by embedding the exact section-name
/// markers our detector keys on into the fixture's section body — the
/// standalone shared fixture always names its section `.test`, but the
/// UPX rule fires on section-name literals appearing anywhere in the
/// file bytes... which it does NOT (it uses the enumerated section
/// list). So instead we exercise the exit code path with the class-
/// level UnknownProtector route: a bare fixture with no imports and
/// entry outside `.text` produces UnknownProtector, and
/// `is_supported_for_devirt() == false` for UnknownProtector, but
/// the CLI treats UnknownProtector as "fall through to F2" per the
/// route in bin/cli.rs. Once Commit F lands with true vendor
/// detection, add a follow-up test here that exercises the exit-3
/// path directly.
///
/// For now, just guard that the CLI's Protector-family log line
/// appears — that's the surface that Commits F/I extend.
#[test]
fn e_protector_family_line_is_logged() {
    let fixture = write_minimal_pe(0x1_4000_0000, 0x1000, &[0x90; 32]);
    Command::cargo_bin("vmp_devirt")
        .expect("cargo bin exists")
        .arg(fixture.path())
        .arg("-v")
        .assert()
        .stderr(predicate::str::contains("Protector family:"));
}

/// Commit R: `--export-analysis` must write a single valid JSON file
/// carrying the unified report shape (protector family, VMP version,
/// handler classifications, ...), even on a bare fixture where no
/// dispatch table is ever located (handler_count stays 0 but the
/// report itself must still serialise cleanly).
#[test]
fn export_analysis_produces_valid_json() {
    let fixture = write_minimal_pe(0x1_4000_0000, 0x1000, &[0x90; 32]);
    let out_dir = tempfile::tempdir().expect("create tempdir");
    let out_path = out_dir.path().join("analysis.json");

    Command::cargo_bin("vmp_devirt")
        .expect("cargo bin exists")
        .arg(fixture.path())
        .args(["--force-version", "vmp35"])
        .arg("--export-analysis")
        .arg(&out_path)
        .assert()
        .success();

    let contents = std::fs::read_to_string(&out_path).expect("analysis report file must exist");
    let json: serde_json::Value = serde_json::from_str(&contents).expect("analysis report must be valid JSON");

    assert_eq!(json["vmp_version"], serde_json::json!("Vmp35"));
    assert!(json.get("protector").is_some(), "report must include a protector field");
    assert!(
        json.get("handler_classifications").is_some(),
        "report must include handler_classifications"
    );
    assert_eq!(json["handler_count"], serde_json::json!(0));
    assert_eq!(json["semantic_coverage_percent"], serde_json::json!(0.0));
}

#[test]
fn f1_vip_defaults_to_pe_entry_point() {
    // image_base 0x00400000 (classic PE32+ non-ASLR base) + entry rva
    // 0x1000 = 0x00401000, which is not 0x140001000.
    //
    // Tightened to match the specific "Starting devirtualization at VIP:
    // 0x401000" log line the CLI emits: a regression that switches the
    // default to any other in-range address (e.g. image_base + 0x1500)
    // would still hit `success()`, since devirtualize_range silently
    // swallows decode errors and returns Ok(vec![]).
    let fixture = write_minimal_pe(0x0040_0000, 0x1000, &[0x90; 32]);

    Command::cargo_bin("vmp_devirt")
        .expect("cargo bin exists")
        .arg(fixture.path())
        .args(["--force-version", "vmp35"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Starting devirtualization at VIP: 0x401000"));
}
