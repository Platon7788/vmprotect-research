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
#[test]
fn f3_force_version_bypasses_non_vmp_gate() {
    let fixture = write_minimal_pe(0x1_4000_0000, 0x1000, &[0x90; 32]);

    Command::cargo_bin("vmp_devirt")
        .expect("cargo bin exists")
        .arg(fixture.path())
        .args(["--force-version", "vmp35"])
        .assert()
        .success();
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
#[test]
fn f1_vip_defaults_to_pe_entry_point() {
    // image_base 0x00400000 (classic PE32+ non-ASLR base) + entry rva
    // 0x1000 = 0x00401000, which is not 0x140001000.
    let fixture = write_minimal_pe(0x0040_0000, 0x1000, &[0x90; 32]);

    Command::cargo_bin("vmp_devirt")
        .expect("cargo bin exists")
        .arg(fixture.path())
        .args(["--force-version", "vmp35"])
        .assert()
        .success();
}
