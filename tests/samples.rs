//! Real-sample validation harness — only compiled under
//! `--features real-samples`. Iterates every `.exe` under
//! `tests/fixtures/<group>/` and asserts the tool produces the
//! expected family/version verdict.
//!
//! This file intentionally makes no assertion when a fixture group (or
//! the whole `tests/fixtures/` tree) is empty — the corpus is
//! user-provided (see `tests/fixtures/README.md`) and CI does not run
//! for this project, so "no samples yet" must be a clean pass, not a
//! failure. See `RESEARCH_GAPS.md` §7 item #9 and `AUDIT_REPORT.md` §5
//! Days 6-7.

#![cfg(feature = "real-samples")]

use assert_cmd::Command;
use std::path::Path;
use walkdir::WalkDir;

/// Exit code for `EXIT_NOT_VMP` (see `src/bin/cli.rs`). Duplicated here
/// rather than imported: the constant is private to the CLI binary and
/// this is an external test crate that only links the library.
const EXIT_NOT_VMP: i32 = 2;
/// Exit code for `EXIT_UNSUPPORTED_FAMILY` (see `src/bin/cli.rs`).
const EXIT_UNSUPPORTED_FAMILY: i32 = 3;

/// One fixture group and the verdict every sample inside it must produce.
struct FixtureGroup {
    /// Subdirectory name under `tests/fixtures/`.
    dir: &'static str,
    /// Expected `ProtectorFamily::as_str()`, or `None` for the
    /// `non_vmp` group (which is expected to fail the family/version
    /// gate rather than report a family at all).
    expected_family: Option<&'static str>,
    /// Expected `VmpVersion::as_str()`, or `None` when the group has no
    /// single expected version (again, `non_vmp`).
    expected_version: Option<&'static str>,
}

const GROUPS: &[FixtureGroup] = &[
    FixtureGroup {
        dir: "vmp1",
        expected_family: Some("VMProtect"),
        expected_version: Some("VMP 1.x"),
    },
    FixtureGroup {
        dir: "vmp2",
        expected_family: Some("VMProtect"),
        expected_version: Some("VMP 2.x"),
    },
    FixtureGroup {
        dir: "vmp30",
        expected_family: Some("VMProtect"),
        expected_version: Some("VMP 3.0-3.4"),
    },
    FixtureGroup {
        dir: "vmp35",
        expected_family: Some("VMProtect"),
        expected_version: Some("VMP 3.5.0-3.5.1"),
    },
    FixtureGroup {
        dir: "vmp36",
        expected_family: Some("VMProtect"),
        expected_version: Some("VMP 3.6-3.10.5"),
    },
    FixtureGroup {
        dir: "non_vmp",
        expected_family: None,
        expected_version: None,
    },
];

/// Per-sample facts scraped out of the CLI's stderr log lines. Every
/// field is `Option` because a sample that fails early (e.g. the F2
/// gate) never reaches the later log lines.
#[derive(Debug, Default)]
struct SampleReport {
    family: Option<String>,
    version: Option<String>,
    dispatch_table_va: Option<u64>,
    handler_count: Option<usize>,
    // Register-role identification (Commit K, `src/register_roles.rs`)
    // has not landed yet. Once it does, populate this from the CLI's
    // "Register roles:" log line and compare it below the same way
    // `family`/`version` are compared.
    #[allow(dead_code)]
    register_roles: Option<String>,
}

impl SampleReport {
    /// Scrape the fields this harness cares about out of one run's
    /// stderr text. Intentionally string-matching rather than a real
    /// parser: the CLI's log format is a stable, deliberately grep-able
    /// contract (see `src/bin/cli.rs` `info!` call sites), not a
    /// machine-readable protocol worth a dependency for.
    fn parse(stderr: &str) -> Self {
        let mut report = SampleReport::default();

        for line in stderr.lines() {
            if let Some(rest) = extract_after(line, "Protector family: ") {
                // "VMProtect (confidence 100/100)" -> "VMProtect"
                let family = rest.split(" (confidence").next().unwrap_or(rest).trim();
                report.family = Some(family.to_string());
            } else if let Some(rest) = extract_after(line, "Detected VMP version: ") {
                report.version = Some(rest.trim().to_string());
            } else if let Some(rest) = extract_after(line, "Dispatch table VA: 0x") {
                report.dispatch_table_va = u64::from_str_radix(rest.trim(), 16).ok();
            } else if let Some(rest) = extract_after(line, "Handlers extracted: ") {
                report.handler_count = rest.trim().parse().ok();
            }
        }

        report
    }
}

/// `line.strip_prefix` equivalent that also tolerates env_logger's
/// `[LEVEL module] ` framing ahead of the message by searching for
/// `needle` anywhere in the line instead of anchoring at offset 0.
fn extract_after<'a>(line: &'a str, needle: &str) -> Option<&'a str> {
    line.find(needle).map(|idx| &line[idx + needle.len()..])
}

/// Aggregate counters across every sample seen, printed as one summary
/// line at the end of the run.
#[derive(Debug, Default)]
struct Aggregate {
    scanned: usize,
    groups_with_samples: usize,
    family_matched: usize,
    version_matched: usize,
    dispatch_table_found: usize,
}

#[test]
fn validate_real_samples() {
    let fixtures_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    if !fixtures_root.is_dir() {
        log_line("tests/fixtures/ does not exist, skipping real-sample validation entirely");
        return;
    }

    let mut agg = Aggregate::default();
    let mut any_group_had_samples = false;

    for group in GROUPS {
        let group_dir = fixtures_root.join(group.dir);
        let samples = find_exe_files(&group_dir);

        if samples.is_empty() {
            log_line(&format!("no samples in tests/fixtures/{}/, skipping", group.dir));
            continue;
        }

        any_group_had_samples = true;
        agg.groups_with_samples += 1;

        for sample in &samples {
            agg.scanned += 1;
            run_one_sample(sample, group, &mut agg);
        }
    }

    if !any_group_had_samples {
        log_line(
            "tests/fixtures/ tree contains no .exe samples in any subdirectory; \
             nothing to validate. Populate tests/fixtures/<vmpN>/ per \
             tests/fixtures/README.md and re-run `cargo test --features real-samples`.",
        );
    }

    log_line(&format!(
        "[samples] scanned {} samples across {} subdirectories: {} matched expected family, \
         {} matched expected version, {} had a dispatch table located.",
        agg.scanned, agg.groups_with_samples, agg.family_matched, agg.version_matched, agg.dispatch_table_found
    ));
}

/// Run the compiled `vmp_devirt` binary against one sample and fold the
/// outcome into `agg`, panicking (failing the test) on a mismatch
/// against `group`'s expectations.
fn run_one_sample(sample: &Path, group: &FixtureGroup, agg: &mut Aggregate) {
    let output = Command::cargo_bin("vmp_devirt")
        .expect("cargo bin exists")
        .arg(sample)
        .output()
        .expect("failed to execute vmp_devirt");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let code = output.status.code();
    let report = SampleReport::parse(&stderr);

    log_line(&format!(
        "[samples] {} -> exit={:?} family={:?} version={:?} dispatch_table_va={:?} handlers={:?}",
        sample.display(),
        code,
        report.family,
        report.version,
        report.dispatch_table_va,
        report.handler_count,
    ));

    match (group.expected_family, group.expected_version) {
        (Some(expected_family), Some(expected_version)) => {
            // A VMP-version group: the tool must run the full pipeline
            // successfully and land on the right family/version.
            assert_eq!(
                code,
                Some(0),
                "{} (group {}) exited {:?}, expected success (0); stderr:\n{}",
                sample.display(),
                group.dir,
                code,
                stderr
            );

            assert_eq!(
                report.family.as_deref(),
                Some(expected_family),
                "{} (group {}) reported family {:?}, expected {:?}",
                sample.display(),
                group.dir,
                report.family,
                expected_family
            );
            if report.family.as_deref() == Some(expected_family) {
                agg.family_matched += 1;
            }

            assert_eq!(
                report.version.as_deref(),
                Some(expected_version),
                "{} (group {}) reported version {:?}, expected {:?}",
                sample.display(),
                group.dir,
                report.version,
                expected_version
            );
            if report.version.as_deref() == Some(expected_version) {
                agg.version_matched += 1;
            }

            if report.dispatch_table_va.is_some() {
                agg.dispatch_table_found += 1;
            }
        }
        _ => {
            // non_vmp group: the F2/F3 family gate must reject the
            // binary rather than run the VMP pipeline against it.
            // EXIT_UNSUPPORTED_FAMILY is accepted alongside
            // EXIT_NOT_VMP because a "clean" sample the user dropped in
            // here could in principle be identified as some other,
            // unsupported protector rather than truly unprotected —
            // both are correct "this is not devirtualisable VMP"
            // outcomes for this gate.
            assert!(
                code == Some(EXIT_NOT_VMP) || code == Some(EXIT_UNSUPPORTED_FAMILY),
                "{} (group non_vmp) exited {:?}, expected EXIT_NOT_VMP ({}) or \
                 EXIT_UNSUPPORTED_FAMILY ({}); stderr:\n{}",
                sample.display(),
                code,
                EXIT_NOT_VMP,
                EXIT_UNSUPPORTED_FAMILY,
                stderr
            );
        }
    }
}

/// Recursively collect every `.exe` file (case-insensitive extension)
/// directly under `dir`, ignoring `.gitkeep` and any non-file entries.
/// Returns an empty vec for a missing or gitkeep-only directory.
fn find_exe_files(dir: &Path) -> Vec<std::path::PathBuf> {
    if !dir.is_dir() {
        return Vec::new();
    }

    WalkDir::new(dir)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("exe"))
                .unwrap_or(false)
        })
        .collect()
}

/// Emit a harness log line. Uses `eprintln!` rather than `log::info!`:
/// `cargo test` captures stdout/stderr per-test by default and only
/// shows it on failure or with `--nocapture`, which is exactly the
/// "quiet unless something needs attention" behavior wanted here — and
/// it avoids depending on a logger being initialized inside the test
/// binary (the CLI's `env_logger::init()` only runs in the separate
/// `vmp_devirt` process `assert_cmd` spawns).
fn log_line(msg: &str) {
    eprintln!("{msg}");
}
