# Real-sample fixtures

This directory is the drop-zone for real VMProtect-protected binaries used
by the `tests/samples.rs` validation harness (gated behind the
`real-samples` Cargo feature — see the repo root `README.md`, "Real-sample
validation"). Nothing in here is required for the default `cargo build` /
`cargo test`; it exists so that the moment you have actual samples, running

```bash
cargo test --features real-samples
```

gives you an immediate pass/fail readout against them.

## Legal note

**Do not commit third-party proprietary binaries to this repository.**
VMProtect-protected executables — even trivial hello-world builds made
with the free/trial version — are derived works containing VMPSoft's
runtime and stub code. `.gitignore` at the repo root excludes
`tests/fixtures/**/*.exe` for this reason. Keep your samples local, or in
a private, access-controlled artifact store outside this repo.

## Where to get samples

- Build your own: install VMProtect Free or Trial from
  https://vmpsoft.com/, protect a minimal "hello world" C/C++ executable
  with default settings, and drop the output `.exe` into the matching
  version subdirectory below.
- Community VMP-sample corpora referenced in `RESEARCH_GAPS.md` /
  `AUDIT_REPORT.md` (research writeups sometimes link sample binaries;
  treat provenance and license of anything downloaded from a third party
  with appropriate caution before running it).
- `non_vmp/` samples can be any clean, unprotected PE — e.g. a binary
  copied from `C:\Windows\System32` or a fresh build of your own trivial
  program.

## CI

There is no CI for this project (project policy — see root `README.md`).
Real-sample validation is local-only and user-provided; there is no
GitHub Actions artifact producing samples on demand. Populate these
directories on your own machine and run `cargo test --features
real-samples` locally.

## Naming convention

`<version>_<compiler>_<mode>.exe`, e.g.:

- `vmp3_mingw_helloworld.exe`
- `vmp2_msvc_helloworld.exe`

The version/compiler/mode fields are documentation for humans skimming
the directory; the harness itself does not parse the filename — it only
cares which subdirectory a `.exe` lives under (see below) and what the
tool reports when run against it.

## Subdirectories

| Directory | Expected content | Expected verdict |
|---|---|---|
| `vmp1/` | Binaries protected by VMProtect 1.x | `family=VMProtect`, `version=VMP 1.x` |
| `vmp2/` | Binaries protected by VMProtect 2.x | `family=VMProtect`, `version=VMP 2.x` |
| `vmp30/` | Binaries protected by VMProtect 3.0-3.4 | `family=VMProtect`, `version=VMP 3.0-3.4` |
| `vmp35/` | Binaries protected by VMProtect 3.5.0-3.5.1 | `family=VMProtect`, `version=VMP 3.5.0-3.5.1` |
| `vmp36/` | Binaries protected by VMProtect 3.6-3.10.5 | `family=VMProtect`, `version=VMP 3.6-3.10.5` |
| `non_vmp/` | Clean, unprotected binaries | F2 non-VMP gate (`EXIT_NOT_VMP`/`EXIT_UNSUPPORTED_FAMILY`) |

## Expected sizes

A VMP3 hello-world build is typically **1-5 MB** (VMProtect's runtime and
virtualized-code overhead dominate a trivial program's own size). Wildly
smaller files (a few KB) are probably not actually virtualized; wildly
larger files (tens of MB) may have bundled extra data and are still fine
to test with, just slower to load.

## Empty directories

Every subdirectory above ships with a `.gitkeep` placeholder so the
directory tree survives `git clone` with no binaries in it. The harness
in `tests/samples.rs` treats an empty (gitkeep-only) subdirectory as
"nothing to check here" and logs a skip line rather than failing.
