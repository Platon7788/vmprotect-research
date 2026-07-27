# Research Gaps — VM Protectors, Obfuscators, Mutators

Snapshot: 2026-07-27. Baseline: `main` after commits `9b2a025` … `d81cfbd` (session 2026-07-26/27).
Scope: Windows PE (x86 / x86-64) protectors and their VM / obfuscation layers.

Legend: ✅ fully covered · 🟡 partial · ⛔ not covered.

---

## 0. TL;DR

**Current tool speaks:** VMProtect only. Five version buckets — 1.x, 2.x, 3.0-3.4, 3.5.0-3.5.1, 3.6-3.10.5 — scored from three signals: `.vmp0`/`.vmp1` section presence, VMP-1-style `pushad; mov esi, imm32; lea edi, [esi+disp]` entry stub, VMP-2/3-style `push imm32; call/jmp rel32` entry stub landing in a `.vmpN` section, plus the literal `"VMProtect"` string and an RWX entry-section check. 8 of ~35 VMP-semantic handler shapes are recognised (`Rdtsc`, `Cpuid`, `Vmexit`, `Nand`, `Nor`, `Push`, `Pop`, `Vjmp`). Dispatch table located by a fallback pointer-run scan over `.text`/`.rdata`/`.vmp*`/`.kbB*`. Operand decryption is a stream `crc = crc*31 + val` recurrence; ALU chains recognise homogeneous NOR/NAND runs and stamp `ADD` / `SUB` / `NOT` / `AND` on the last instruction of the run.

**Current tool misses (headline):**
- Every non-VMProtect protector — Themida/WinLicense, Code Virtualizer, Enigma, Obsidium, Denuvo, ExeCryptor, SafEngine — is `Unknown`.
- No class-level "some protector" gate (entropy / W+X / stripped-IAT / EP-outside-`.text`), so a renamed-section VMP or Themida returns `Unknown` at confidence 0 with no useful fallback.
- 27 of the ~35 VMP-semantic handlers are unimplemented (LDD, STR, MUL, DIV, IDIV, IMUL, shifts, rotates, POPF, RET, VEMIT, VEXEC, VNOP, VUNK, LOCKOR, VPUSHCR0/3, VSETVSP, POPSTK, PUSHSTK, PUSHREG, POPREG).
- Fingerprint matchers use "presence anywhere in the first 100 bytes" checks, so a handler decorated with 0-3 junk instructions between real ones (VMP 3.x default) still matches but any lifter downstream will misread its operands.
- The `crc*31 + val` recurrence in `OpcodeCryptor` is a placeholder unmapped to any published VMP version; no cross-check exists against a real VMP-decrypted operand stream.
- No control-flow-flattening removal, no MBA simplification, no junk-code stripping, no register-role canonicalisation, no import-table rebuild, no self-modifying-code / TLS-callback bootstrap detection.

**Next-biggest wins by effort:**
- Add the class-level "some protector" gate and per-vendor section-name / EP-byte matcher table for Themida, Enigma, Obsidium, Code Virtualizer, ASPack/ASProtect, Armadillo, UPX/MPRESS/Petite (small, well-documented byte tables, ~1-2 day effort, immediate coverage jump).
- Implement the missing high-frequency VMP semantic matchers — `Add`, `Ret`, `Ldd`, `Str`, `Vsetvsp`, `Popf`, plus differentiating `PushImm` / `PushReg` — because these dominate any real virtualised function body (~3-5 days, verifiable once real samples land).
- Introduce a liveness / junk-code stripper as a pre-matcher pass so signature fragility drops as build-to-build variance rises (~2-3 days for a first-cut peephole + backward-taint version; unlocks correct matching on VMP 3.x mutated handlers).

---

## 1. Coverage matrix — what we detect vs what exists

Sources: `src/version.rs`, `src/version_matchers.rs`, `src/dispatch_table.rs`, `src/handler_semantic.rs`, `src/handler_classifier.rs`.

| Family / Vendor | Sub-variants | Currently detected? | Currently classified (version)? | Handler patterns understood? | Notes |
|---|---|---|---|---|---|
| **VMProtect** | 1.x | 🟡 | 🟡 (`VmpVersion::Vmp1`, heuristic) | 🟡 (8 of ~35 semantic shapes; x86-instr-level ~20 first-byte patterns as fallback) | Only via section-absent + `pushad;mov esi,imm32` + RWX entry (`version.rs:110-142, 202-215`). No entry-stub crypto recovery. |
| VMProtect | 2.x | 🟡 | 🟡 (`Vmp2`) | 🟡 | `push imm32;call/jmp rel32` landing in `.vmp0` (`version.rs:151-198`). |
| VMProtect | 3.0 – 3.4 | 🟡 | 🟡 (`Vmp30`) | 🟡 | Detected via "no `.vmp*` sections + standard `.text/.rdata`" fallback rule (`version.rs:120-128`). |
| VMProtect | 3.5.0 – 3.5.1 | 🟡 | 🟡 (`Vmp35`) | 🟡 | Both `.vmp0` + `.vmp1` present (`version.rs:111-112`). |
| VMProtect | 3.6 – 3.10.5 | 🟡 | 🟡 (`Vmp36Plus`) | 🟡 | Exactly one of `.vmp0`/`.vmp1` (`version.rs:114-119`). |
| VMProtect | 3.7+ merged handlers | ⛔ | ⛔ | ⛔ | README §Known Limitations #1: classifier assumes 1 opcode → 1 handler; merged handlers break it. `handler_semantic.rs` matchers key on one shape per fingerprint. |
| VMProtect | 3.11+ (.NET, RDGSBASE, MinGW, Win11 24H2 virtual DLLs) | ⛔ | ⛔ | ⛔ | No dedicated version bucket; `handler_classifier.rs` byte tables would miss new opcodes. |
| VMProtect | ZwProtectVirtualMemory (3.x) vs VirtualProtect (2.x) marker | ⛔ | ⛔ | — | No string-scan rule for `ZwProtectVirtualMemory` in `version.rs` — would raise 3.x confidence cheaply. |
| **Themida / WinLicense** | 1.x–1.9 (fixed EP prelude) | ⛔ | ⛔ | ⛔ | `version.rs` only checks `.vmp*` names. No `.themida` / `WinLicen` / `.winlice` / whitespace-name matcher. |
| Themida | 2.x, 3.x (post-2020, per-build randomised section names) | ⛔ | ⛔ | ⛔ | Structural signals (RSP = VSP, 2-byte opcodes, nested VMs) not modelled. |
| Themida VM flavors | FISH / TIGER / DOLPHIN / PUMA / SHARK / LION × CISC / CISC-2 / RISC-64 / RISC-128 × White/Red/Black | ⛔ | ⛔ | ⛔ | Per-instance regenerated ISA — no fixed handler taxonomy possible. |
| **Code Virtualizer** (Oreans standalone) | 1.3.x – 2.2.x | ⛔ | ⛔ | ⛔ | Central `lodsb ; movzx eax,al ; jmp [edi+eax*4]` dispatcher fingerprint (`AC 0F B6 C0 FF 24 87`) not scanned. |
| Code Virtualizer | Stealth mode (VM inlined) | ⛔ | ⛔ | ⛔ | Requires dispatcher-shape scan inside `.text`; not implemented. |
| **Enigma Protector** | 1.x – 3.79 | ⛔ | ⛔ | ⛔ | `.enigma0` … `.enigma3` section names + `"ENIGMA"` marker + Neo23x0 YARA byte runs — none scanned. |
| Enigma | 3.80+ (new VM, no public devirt) | ⛔ | ⛔ | ⛔ | Even research is thin; would need original RE. |
| Enigma Virtual Box | (VFS wrapper, distinct product) | ⛔ | ⛔ | — | `.enigma1` / `.enigma2` sections in `.rsrc`. |
| **Obsidium** | 1.3.x – 1.7.x | ⛔ | ⛔ | ⛔ | No fixed section names; DIE's `Obsidium.2.sg` entry-stub pattern (`EB 03 ?? ?? ?? E8 …`) not implemented. |
| **Armadillo / SoftwarePassport** | 3.x – 9.x (legacy) | ⛔ | ⛔ | ⛔ | `.text1` / `.adata` / `.pdata` names, `60 E8 00 00 00 00 5D 81 ED` prelude, `"CopyMemII"` string — none matched. |
| **ASPack / ASProtect** | current | ⛔ | ⛔ | ⛔ | `.aspack` / `ASPack` / `.adata` sections, `60 E8 03 00 00 00 E9 EB 04 5D` prelude — none matched. |
| **ExeCryptor** | 2.0 – 2.6 (unmaintained) | ⛔ | ⛔ | ⛔ | Low corpus prevalence; legacy. |
| **SafEngine Shielden** | 2.1.9 – 2.4.0 | ⛔ | ⛔ | ⛔ | Per-instance random ISA; dynamic-only tooling in the wild (UnSafengine64, Pin-based). |
| **Denuvo Anti-Tamper** | per-title custom | ⛔ | ⛔ | ⛔ | Bespoke `.vm`-section stack machine; not a VMP-family. Recommended action: detect & refuse. |
| Denuvo-inside-VMP (e.g. AC Origins) | outer VMP + inner Denuvo | 🟡 | 🟡 (outer VMP only) | ⛔ | We'd detect the outer `.vmp*` wrapper; inner `.vm` remains opaque. |
| **BattlEye (BEDaisy.sys)** | current | ⛔ | ⛔ | 🟡 | Customised VMP 2/3 with scrubbed section names (`.be0`); dispatcher shape is stock VMP. Byte-signature matchers miss it — structural VMP-3 matchers would fire. |
| **EasyAntiCheat (EAC)** | ≤2021 driver | ⛔ | ⛔ | 🟡 | Single-VM VMP 2 in driver — ideal target case if section-name matcher were structural rather than literal. |
| EAC modern | proprietary integrity VM | ⛔ | ⛔ | ⛔ | Non-VMP secondary VM. |
| **Riot Vanguard (stub.dll)** | Packman shell + VMP 3 detection routines | ⛔ | ⛔ | 🟡 | Packman itself is not VMP; VMP-3 sub-routines would classify if unpacked first. |
| Riot Vanguard (vgk.sys) | kernel driver, dispatch-table hooks, PML4 clones | ⛔ | ⛔ | ⛔ | No VM at all; out of scope for a devirtualiser. |
| **Compressor tier** (UPX, MPRESS, Petite, PECompact, Upack) | vanilla + forks | ⛔ | ⛔ | — | Should short-circuit ("compressed, not virtualised") to save effort; currently just returns `Unknown`. |
| **Obfuscator-LLVM (OLLVM)** | `-fla`, `-sub`, `-bcf` | ⛔ | ⛔ | ⛔ | CFF dispatcher recognition + `x*(x+1)%2==0` opaque-predicate signature would flag it. |
| **Tigress** | Virtualize (9 dispatch types), Flatten, EncodeArithmetic | ⛔ | ⛔ | ⛔ | Symbol-name length >200 chars in `.rodata` is a distinctive tell. |
| **Hikari** | StringEncryption, IndirectBranch, AntiClassDump | ⛔ | ⛔ | ⛔ | Runtime-decrypt thunk + Obj-C class-registration loops — not scanned. |
| **Metamorphic engines** (RPME, TPE, MetaPHOR, Simile) | legacy | ⛔ | ⛔ | ⛔ | Historical, low corpus. |
| **Anti-debug VM shell** (small VMP2 hosting only anti-debug) | pattern | 🟡 | 🟡 (as generic VMP2) | 🟡 (partial via `Cpuid`/`Rdtsc` matchers) | Our VMP-2 shape matches; we'd not distinguish "anti-debug only" from "full app virtualisation". |

---

## 2. Detection surface gaps

Grouped by "cheap to add" (byte-table only, no new abstraction) vs "requires new abstraction" (needs a new scanner, a new IR, or a new pass).

### 2.1 Cheap to add — byte / section-name tables

All of these can go into a table analogous to `EntryStubMatcher::PUSH_IMM32` / `MOV_ESI_IMM32` in `src/version_matchers.rs`, plus a section-name lookup table alongside the current inline `has_vmp0`/`has_vmp1` checks in `version.rs:95-98`.

| Vendor | Signal | Concrete pattern | Cost |
|---|---|---|---|
| Themida / WinLicense | Section-name allowlist | `Themida`, `.Themida`, `.themida`, `WinLicen`, `.winlice`, `"   "` (3-space), `"        "` (8-space) | ~1h |
| Themida | Entry-stub v1.x compressed | `B8 00 00 ?? ?? 60 0B C0 74 58 E8` (wildcards on imm) | ~1h |
| Themida | Entry-stub v1.x uncompressed | `55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA` | ~1h |
| Themida | Entry-stub DLL v1.8–1.9 | `B8 ?? ?? ?? ?? 60 0B C0 74 68` | ~1h |
| Themida | String marker | `"Themida"`, `"WinLicense"`, `"Oreans"` in raw bytes | ~30m |
| Code Virtualizer | Dispatcher fingerprint | `AC 0F B6 C0 FF 24 87` (`lodsb; movzx eax,al; jmp [edi+eax*4]`) — cheap to scan `.text` + last section | ~1h |
| Enigma | Section-name allowlist | `.enigma0`, `.enigma1`, `.enigma2`, `.enigma3` | ~30m |
| Enigma | String markers | `"Enigma protector v"` in `.data`, `"ENIGMA"` token, `"P.rel$oc$"` | ~30m |
| Enigma | Entry-stub prelude | `60 E8 00 00 00 00 5D 8B D5 81 ED` | ~1h |
| Obsidium | Entry-stub short-jump anti-disasm | `EB 03 ?? ?? ?? E8 ?? ?? ?? ?? 58` | ~1h |
| Armadillo | Section marker | `.text1`, `.adata`, `.data1`, `.pdata` | ~30m |
| Armadillo | Entry-stub prelude | `60 E8 00 00 00 00 5D 81 ED` | ~1h |
| Armadillo | String marker | `"CopyMemII"` | ~15m |
| ASPack / ASProtect | Section names | `.aspack`, `ASPack`, `.ASPack`, `.adata` | ~30m |
| ASPack | Entry prelude | `60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3` | ~1h |
| Compressors — UPX vanilla | Section names | `UPX0`, `UPX1`, `UPX2` | ~15m |
| Compressors — MPRESS | Section names | `.MPRESS1`, `.MPRESS2` | ~15m |
| Compressors — Petite | Section names | `.petite` | ~15m |
| Compressors — PECompact | Section names | `PEC2TO`, `PEC2`, `pec1..pec6`, `PEC2MO` | ~30m |
| Compressors — Upack | Section names | `.Upack`, `.ByDwing` | ~15m |
| VMProtect version discriminator (3.x vs 2.x) | String marker | `"ZwProtectVirtualMemory"` in raw bytes | ~15m |
| VMProtect anti-VM lookup | String marker | `"VBoxRev"`, `"VBoxVer"` | ~15m |
| Denuvo (reject signal) | Section marker | Section literally named `.vm` (case-sensitive) | ~15m |
| BattlEye BEDaisy | Section marker | `.be0` (literal) | ~15m |
| Vanguard stub.dll (Packman) | Section marker | Two PE sections both named `.stub` | ~30m |

**Total cheap tier**: on the order of 1-2 days of straightforward matcher-table work, unlocking coverage on 8-10 additional families.

### 2.2 Class-level "some protector" gate

None of these exist in the current tool. Add before per-vendor scans so renamed-section VMP or Themida still gets a truthful classification.

| Signal | Threshold | Backing research |
|---|---|---|
| Section Shannon entropy | any non-`.rsrc` section > 7.0 bits/byte | PE-LiteScan, REMINDer, DiE |
| W+X section | any section has both `IMAGE_SCN_MEM_WRITE` and `IMAGE_SCN_MEM_EXECUTE` | universal packer trait |
| Stripped IAT | ≤ 12 imports, dominated by `LoadLibraryA` / `GetProcAddress` / `VirtualProtect` / `VirtualAlloc` / `ExitProcess` | MITRE T1027.007 |
| Entry-point outside `.text` | `AddressOfEntryPoint` falls in packer stub section | universal |
| `VirtualSize` >> `SizeOfRawData` | ratio > 4 | universal for decompression-in-place |
| Overlay heuristic | raw file size > sum of `SizeOfRawData`; overlay entropy > 7.5 | Enigma Virtual Box, some Themida configs |
| Rich header discrepancy | absent-on-claimed-MSVC OR import count mismatch > 50% | Kalnai/Poslušný VB2019 |
| TLS callback present | AddressOfEntryPoint outside `.text` + `AddressOfCallBacks != 0` | Themida / WinLicense loader trick |
| PE header anomaly matrix | `NumberOfRvaAndSizes ∉ {0,16}`, `SizeOfHeaders > 0x400`, section with non-standard alignment | Themida, ASProtect variants |
| Non-ASCII or space-padded section names | 3-space / 8-space names | Themida 2.1.x / 3.0.x |

**Cost**: ~1 day for the gate + a scored aggregator similar to `RuleScore` in `version.rs`.

### 2.3 Requires new abstraction

| Signal | What it needs | Backing research |
|---|---|---|
| Handler dispatcher shape (structural VMP identification when section names are scrubbed) | Instruction-window disassembler, not byte-window; run over every RX section, find `mov r,[VIP]; xor r,key; add r,tbl; jmp [r]` triples | BattlEye / EAC signature-scrub scenario; NoVmp / vmpattack rely on this |
| Denuvo `.vm` fingerprint | Track scattered DWORD writes into `.vm` during pre-OEP execution; `xchg reg,[rsp] ; ret` dispatch pairs; encrypted `0F A2` (CPUID) with `pause; test; jnz` spin-lock guards | Requires abstract interpretation or emulator |
| Packman fingerprint | Two `.stub` sections + nopped OEP + VEH handler + `SEC_NO_CHANGE` (`0x00400000`) flag on `NtMapViewOfSection` | Requires import-argument tracking |
| EAC IOCTL fingerprint | Immediates `0x226003`, `0x22E007`, `0x22E01F` in `.rdata` or as `mov` immediates; crash-on-integrity `mov [inv], reg` with `0xEAC` | Requires immediate-value scan across `.rdata` + code |
| Themida VJCC handler | Bytecode-indexed jump table + write-back to a VIP field inside a PE section | Requires per-section liveness / def-use |
| Handler-body CRC loops (Denuvo) | `pcmpeqb / crc32 / xor-fold` over a handler byte range | Requires pattern DB of crypto shapes |
| Anti-debug catalogue (post-detection classification) | Constants `0x30/0x60/0x68/0xBC` (PEB offsets), info-classes `0x7/0x1E/0x1F/0x23`, `0xC0000008` (CloseHandle trick), `CONTEXT_DEBUG_REGISTERS` (0x10) — all as immediates | Check Point anti-debug wiki, al-khaser |

---

## 3. Handler / semantic classifier gaps

Sources: `src/handler_semantic.rs:36-95` (enum), `src/handler_semantic.rs:97-160` (matcher), `AUDIT_REPORT.md` §Q2 (cross-validated taxonomy).

### 3.1 Missing VMP semantic matchers — prioritised by expected frequency

Frequency estimated from the vmpattack / NoVmp write-ups plus the cyber.wtf / hackyboiz / vxcall dispatch anatomy — a typical virtualised x86 function is dominated by data-movement + arithmetic base + control-flow-exit handlers.

| Priority | Semantic | Why load-bearing | Distinguishing shape (from research) |
|---|---|---|---|
| P0 | `Add` | Every arithmetic op currently reduces to a NOR-chain — but a real `ADD` handler exists in VMP for the flag-affecting case. Compilers emit it constantly. | Reg-reg or [VSP]/[VSP+n] load, `add reg,reg`, `pushfq`, store flags. |
| P0 | `Ret` | Every virtualised function ends here. Currently confused with `Vjmp` (documented in `handler_semantic.rs:14-19`). | Distinguishable only by prior handler being CALL-style vs `PUSH_IMM` — needs cross-handler state, not stateless matcher. |
| P0 | `Ldd` | LoaD DWord/QWord from memory — every virtualised program that touches globals or heap uses this. | Load `[VSP]` → address, load `[address]`, store `[VSP]`, adjust VSP. |
| P0 | `Str` | Store to memory — mirror of `Ldd`. | Load `[VSP]` → value, load `[VSP+n]` → address, store `[address], value`, adjust VSP. |
| P0 | `Vsetvsp` | Frame setup / teardown in virtualised prologues/epilogues. | `mov VSP, [VSP]` (pop value into VSP itself), no store. |
| P1 | `PushImm` vs `PushReg` differentiation | Push is currently a single fingerprint (`handler_semantic.rs:24-26`). Every function prologue and every immediate constant push a `PUSH`. | `PushReg`: load from VM context `[CTX+disp]`, sub VSP, store `[VSP]`. `PushImm`: load from VIP (bytecode operand), sub VSP, store `[VSP]`. |
| P1 | `Popreg` | Pop-into-context for register restore in epilogues. | Load `[VSP]`, add VSP, store `[CTX+disp]` — currently matches `Pop` shape. |
| P1 | `Popstk` / `Pushstk` | VM-stack↔VM-stack transfers. | Load `[VSP]`, sub VSP, store `[VSP]` — no CTX write. |
| P1 | `Popf` | Flags restore after each ALU. | POPFQ (`9D`) or POPFD (`9D`) within the handler body but NOT followed by RET (that shape is `Vmexit`, already matched). |
| P2 | `Shl` / `Shr` / `Shld` / `Shrd` | Compiler-emitted for multiply-by-power-of-2, bitfield extraction. | `shl/shr/shld/shrd reg,cl` on VM-stack values. |
| P2 | `Rcl` / `Rcr` | Rare in compiler output; present because VMProtect virtualises every native x86 op. | ROL/ROR encoding on VM-stack values. |
| P2 | `Mul` / `Imul` / `Div` / `Idiv` | Present but low frequency; VMP virtualises the full x86 semantics including DX:AX / EDX:EAX pairing. | Group-3 opcodes `F6/F7` with `/4/5/6/7` mod-fields. |
| P3 | `Lockor` | Atomic-op wrappers, rare outside multithreaded code. | `LOCK` prefix (`F0`) + `OR` opcode. |
| P3 | `VpushCr0` / `VpushCr3` | Ring-0 / anti-debug probe (drivers only). | `mov reg, cr0` / `mov reg, cr3` (`0F 20 C0` / `0F 20 D8`) — 2-byte opcodes distinctive. |
| P3 | `Vemit` | Escape — raw x86 emitted verbatim from bytecode operand. | Handler ends with `jmp reg` where `reg` was computed from VIP contents — control returns to native x86, not to dispatcher. |
| P3 | `Vexec` | Nested VM entry. | Handler branches into another VM entry stub. |
| P3 | `Vnop` | Padding, rarely emitted by compilers via VMP. | Handler body is only VIP-advance + dispatcher jump, no VSP or CTX touch. |
| P3 | `Vunk` | VMP-internal for unhandled opcodes; useful sentinel. | Trap/int3 or fixed error handler tail. |

### 3.2 Which of the current 8 matchers generalise cross-vendor

| Current matcher | VMProtect | Themida | Code Virtualizer | Enigma | Denuvo |
|---|---|---|---|---|---|
| `Rdtsc` (raw `0F 31`) | ✅ | ✅ (any protector inlining rdtsc) | ✅ | ✅ | 🟡 (Denuvo encrypts CPUID pages, may also encrypt rdtsc) |
| `Cpuid` (raw `0F A2`) | ✅ | ✅ | ✅ | ✅ | ⛔ (Denuvo stores `0F A2` encrypted, guarded by spin-lock — matcher would miss) |
| `Vmexit` (POPFQ/POPAD → RET within 32 bytes) | ✅ | ⛔ (Themida VMs don't use x86 RET to leave a VM; they context-switch inside the binary) | 🟡 (CodeVirt handlers are individual, no single vmexit) | ⛔ | ⛔ |
| `Nand` / `Nor` (2+ NOTs + AND/OR reg-reg) | ✅ (De Morgan is VMP's ALU signature) | ⛔ (Themida uses named-animal VMs with different ALU shape) | ⛔ | ⛔ | ⛔ |
| `Push` (`MOV r,[r]` + `SUB r,imm8` + `MOV [r],r`) | ✅ | ⛔ (RSP is VSP — push handlers look like native `push`; `MOV [rsp],r` shape only) | 🟡 (ESI is VIP but VSP is separate) | ⛔ (undocumented) | ⛔ |
| `Pop` (`MOV r,[r]` + `ADD r,imm8` + `MOV [r+disp],r`) | ✅ | ⛔ (same reason) | 🟡 | ⛔ | ⛔ |
| `Vjmp` (load + VSP adjust + indirect JMP, no store) | ✅ | ⛔ (Themida VJCC uses jump-table indexed by bytecode byte, writes back to VIP field in-binary) | 🟡 | ⛔ | ⛔ |

**Interpretation**: only the two 2-byte raw-opcode matchers (`Rdtsc`, `Cpuid`) are truly vendor-independent. The 5 others are VMProtect-shaped and will produce **false negatives** on Themida (RSP = VSP), Code Virtualizer (different register conventions), and Denuvo (encrypted opcodes).

**What Themida needs specifically** (per §Themida in commercial-vm-protectors research):
- Recognise that VSP is native RSP; a "push" handler is any `mov [rsp-8], reg; sub rsp, 8`-shape sequence.
- 2-byte opcode reader — the current implicit assumption of 1-byte opcodes drops immediately.
- Per-flavor ISA table — impossible without either dynamic instrumentation (Pin-style) or static symbolic execution of each handler to recover semantics (Themida-unmutate / Miasm route).

**What Code Virtualizer needs**:
- Recognise the central switch dispatcher `AC 0F B6 C0 FF 24 87` and treat the reachable handler table as ground truth.
- 1-byte opcodes into ESI (x86) — width parameter needs to be per-vendor.
- EBX as rolling key — different single-register cipher, not VMP's memory-stored CRC.

### 3.3 MBA / opaque-predicate simplification

**Current state**: not implemented. `handler_semantic.rs` treats a handler body as a byte window and does "presence anywhere" checks. Junk arithmetic (`add rax,K; sub rax,K` pairs, `xor eax,eax; add eax,x` chains, MBA-encoded flag ops) is not folded away.

**Minimal scope** (post-dispatch-table extraction, before handler-semantic matching):

| Pass | What it does | Cite tool |
|---|---|---|
| Peephole junk stripper | Remove `mov r,r`, `xchg r,r`, `lea r,[r]`, `lea r,[r+0]`, push/pop pairs with no intervening use | mrphrazer `obfuscation_detection`, MITRE T1027.016 |
| Backward liveness | Compute def-use per handler body; drop instructions with no live output | Triton / angr `SimEngine` (behavior only, not source) |
| Constant folding / algebraic simplification | Fold `(x^y)+2*(x&y)` → `x+y`, `-(-x-y)` → `x+y`, etc. | msynth, MBA-Blast, GAMBA, ProMBA — all behavior-only references |
| Opaque-predicate solver (linear only, not path-explosion) | Detect and eliminate `x*(x+1)%2==0`-style branches | UGent abstract interpretation, arXiv 1909.01640 (~98% on OLLVM) |

Nothing GPL to copy — the algorithms are all publishable, only implementation is copyrighted. Tools to study for method (never source):
- **msynth** (mrphrazer, permissive) — MBA simplification via program synthesis.
- **QSynth** (BAR 2020, NDSS paper) — MBA + data encoding + virtualization simplifier; ~20× faster than Syntia.
- **Souper** (Google, Apache 2.0) — SMT-driven superoptimizer; used by Thalium after LLVM passes plateau.

---

## 4. Dispatch / bytecode / crypto gaps

Sources: `src/dispatch_table.rs`, `src/bytecode.rs`, `src/decrypt.rs`, `src/alu.rs`.

### 4.1 Dispatch table location

Current strategy (`dispatch_table.rs:44-72`): try `.text`, then `.rdata`, then any section starting with `.vmp` or `.kbB`. Fallback scan looks for 256 consecutive pointers within `[image_base, image_base + 0x8000_0000)`.

**Gaps by vendor**:

| Vendor | Where dispatch table actually lives | Our fallback finds it? |
|---|---|---|
| VMProtect 1.x/2.x | `.vmp0` (or renamed section); handler table indexed by first virtual operand | 🟡 — depends on section name; renamed builds miss |
| VMProtect 3.0+ | **No dispatch table.** Threaded dispatch: each handler ends with `mov key,[VIP]; xor key,r9; jmp [key+table]` — the "table" is implicit in the handler-tail jump math | ⛔ — the 256-pointer-run scan cannot find something that isn't laid out that way |
| Themida | Per-flavor handler table, section-name randomised | ⛔ |
| Code Virtualizer | Handler table pointed at by EDI in the dispatcher (`AC 0F B6 C0 FF 24 87`); in last section by default, in `.text` in Stealth mode | ⛔ — no dispatcher-fingerprint scan |
| Enigma (post-3.80) | Undocumented | ⛔ |
| Obsidium | Per-instance; no fixed section | ⛔ |
| ExeCryptor | Small fixed-ISA table | 🟡 — 256-pointer scan would trip if table is 256-wide |
| SafEngine | Per-instance random ISA | ⛔ |
| Denuvo | Handler pointers scattered non-contiguously in `.vm`; classic 256-pointer scan will not fire | ⛔ |
| BattlEye BEDaisy | Same as VMP but section renamed | 🟡 — the "starts with `.vmp` or `.kbB`" fallback won't hit `.be0` |
| EAC | Single-VM VMP2 | ✅ if section names present |

**Key finding**: VMP 3.x is **not table-based**. Our tool logs "Found dispatch table at VA: 0x…" and extracts 256 handler addresses via `DispatchTableLocator::extract_handlers` (`dispatch_table.rs:149-215`), but for VMP 3.x, those 256 addresses are the *initial fetch of the FDJ chain*, not a lookup table. The `XorKeyAnalyzer` (`src/xor_key_analyzer.rs`) then tries to XOR-decrypt them with immediates from a preceding pattern-match — but the actual per-handler decryption in VMP 3.x is self-modifying and register-role-randomised. This is a known-fragile path.

### 4.2 Operand crypto — what's known vs what we implement

**Status update (Commit M):** `OpcodeCryptor` now dispatches over a
`CryptoScheme` enum with per-version backends. `CryptoScheme::for_version`
picks: `None` (Vmp1), `Vmp2Rolling` (Vmp2), `Vmp3PerHandler` (Vmp30/35/36),
`Placeholder` (Unknown, backward-compat). `devirtualize_range` selects
the scheme once per range and logs the choice. The `crc*31+val` recurrence
is retained as the `Placeholder` variant so pre-existing test vectors keep
passing. **Validation against real samples still remains open** — Days 6-7
in AUDIT_REPORT.md are blocked on VMP-protected fixture availability.

Historical implementation before Commit M (`src/decrypt.rs`):
```rust
pub fn decrypt_operand(&self, encrypted_byte: u8, _cryptor_size: usize) -> u8 {
    let crc_low = (self.crc_value & 0xFF) as u8;
    encrypted_byte ^ crc_low
}
pub fn update_crc(&mut self, operand_value: u8) {
    self.crc_value = self.crc_value.wrapping_mul(31).wrapping_add(operand_value as u64);
}
```

The `crc*31 + val` recurrence is **not documented anywhere in the VMP literature** surveyed. The back.engineering VMP 2 series, the r0da series, the vxcall 3.8.1 write-up, and the hackyboiz LLVM series describe a stream cipher where each handler decrypts its own operand using a rolling key held in a register (`r9`, `rdi`, `rbx`, or `rbp` depending on VMP 3.x instance) — not a global CRC state maintained across handlers.

**What the research says the real cipher is**:

| Version | Cipher shape | Key material |
|---|---|---|
| VMP 1.x / 2.x | Rolling chain of arithmetic transformations: `add / sub / inc / dec / not / neg / shl / shr / ror / rol / BSWAP` in random per-build order over each operand byte | Extracted from `.text` via XOR-imm32 pattern scan (roughly what `XorKeyAnalyzer` attempts) |
| VMP 3.0 – 3.6 | Self-modifying XOR key in memory (VKEY register: `r9` / `rdi` / `rbx` / `rbp`), FDJ (fetch-decrypt-jump): `read 4-byte offset ; XOR VKEY ; randomised inverse ops (neg, rot, inc) ; XOR VKEY again ; add to handler base ; jmp` | Per-handler bytecode fetch mutates VKEY, so patching bytecode desyncs everything |
| VMP 3.7+ | Same as 3.6 + merged handlers (one native handler now covers several logical ops) + multiple stubs per VM call | Same; multiple stubs mean any tool that stopped at first RET is inoperable |

**Other vendors' operand crypto**:

| Vendor | Cipher |
|---|---|
| Themida | Per-flavor + per-build randomised; VIP is variable-length (VIP += `*(int*)VIP`); dispatcher tail: `key ^= 0x3F8BFC4F ; key &= index` |
| Code Virtualizer | Single-register rolling key in EBX; each handler mutates EBX to decrypt next operand |
| Denuvo | White-box AES-like transforms binding bytecode to hardware fingerprint; opcode-level XOR/rolling keys |
| SafEngine | Per-instance random |

**Implication**: `OpcodeCryptor::decrypt_operand` is a placeholder that will decrypt *something* for any byte stream but cross-verifying it against a real VMP-decrypted operand has not been done (no real sample validation, per §Q2 in `AUDIT_REPORT.md`). Real fix requires (a) per-version cipher (start with VMP 2.x's rolling arithmetic chain — documented in back.engineering VMP 2 write-up), (b) key material recovered per-handler from the FDJ tail rather than a global state, and (c) integration test against a captured operand stream from a known VMP build.

### 4.3 ALU chain reconstruction

Current implementation (`src/alu.rs:33-53, 105-148`) recognises homogeneous NOR/NAND runs and maps:
- 1× NOR → `Not`
- 2× NAND → `And`
- 3× NOR → `Sub`
- 4× NOR → `Add`

**Which VMs actually use De Morgan chains** (per commercial-vm-protectors research):

| Vendor | ALU strategy |
|---|---|
| VMProtect | De Morgan is *the* signature: NAND/NOR primitives compose into ADD/SUB/AND/OR/XOR/NOT. Our matcher family fits VMP well. |
| Themida | Richer ALU per flavor; DOLPHIN uses direct arithmetic, TIGER uses register-file mutation, PUMA/SHARK use larger primitives. **No** De Morgan reduction. |
| Code Virtualizer | Direct arithmetic; each of ~150 opcodes has its own handler. No De Morgan. |
| Enigma | Register-VM hybrid (v6+); undocumented |
| Denuvo | Direct arithmetic + white-box crypto. No De Morgan. |
| SafEngine | Per-instance random |

**Gap**: our matcher is VMP-specific and correctly so. It should not be generalised to other vendors — for them, direct-arithmetic matchers (already in `handler_semantic::VmpSemantic::Add` etc.) are the correct primitive.

**Missing on the VMP side**: mixed chains (a NAND run followed immediately by a NOR run in the same expression) are not recognised — `reconstruct_alu_chains` (`alu.rs:105-148`) resets at every handler-name change. XOR is not directly synthesisable in the current pattern table (would take `NOR(NOR(a,b), NAND(a,b))` = XOR, a 3-op mixed chain). Longer runs than 4× NOR are unhandled.

---

## 5. Obfuscation / mutator gaps

None of the following are implemented. All are prerequisites to reliable handler recognition on modern (2024+) VMP / Themida builds.

| Gap | Where it matters | Backing tool / paper |
|---|---|---|
| Control-flow-flattening (CFF) unflattening | OLLVM `-fla` output; VMProtect wraps handlers *and* the entry stub with a CFF variant; Themida uses trampoline-based flattening; back.engineering, nac-l, and hackyboiz all describe VMP devirt as "just flattening removal". Real-world impact: every function inside a VMP or Themida binary looks flattened before the VM runs. | MODeflattener (Miasm), Quarkslab OLLVM deobf, RPISEC llvm-deobfuscator |
| MBA rewriting | VMP 3.x emits linear MBAs on flag computations; Loki (5.3k unique MBAs) and Tigress EncodeArithmetic are the hardest targets | msynth (mrphrazer), MBA-Blast (USENIX'21), QSynth (BAR'20), ProMBA (CCS'23) — all reference only |
| Junk / dead-code stripping | **This is our single biggest volume problem.** VMP fills handler epilogues and vmenter/vmexit paths with ~60% dead bytes. Our `SemanticMatcher` uses "presence anywhere" checks (`handler_semantic.rs:217-262`), so a handler decorated with junk still matches — but any downstream lifter interpreting operand offsets will be wrong by the junk length. | Backward liveness (Triton / angr behaviour), peephole rules in Binja / Ghidra IR, obfuscation_detection Binja plugin |
| Register-role canonicalisation | VMP 3.x randomises VIP ∈ {rsi, rbp, r11, rdi}, VSP ∈ {r10, r9, rsi}, VKEY ∈ {r9, rdi, rbx, rbp}, handler-base ∈ {rdi, r11, rbp, rbx} per VM instance. Our matchers implicitly assume a fixed convention (via `skip_rex` and by matching on opcode + mod-form, ignoring reg fields). This is why current matchers *do* work across instances — but as soon as a real lifter needs to know which register is VIP, it breaks. | NoVmp / vmpattack solve this via data-flow analysis assigning role-based virtual regs |
| Import table restoration | Currently relies on external tools (Scylla). VMP redirects each import call through the VM (`push reg / call resolver / ret` triples in 2.x-3.6; chained `lea/mov/lea` stubs in 3.7+). Without IAT recovery, every `call [import]` in the devirtualised output is a raw pointer. | vmpfix (archercreat, permissive), vmpdump (0xnobody, GPL-3.0 — reference only), VMPImportFixer (mike1k) |
| CFF opaque predicates | OLLVM `-bcf` inserts `x*(x+1)%2==0`-style always-true conditions. Present around VMP handlers and inside anti-debug shells. | UGent abstract interpretation, arXiv 1909.01640 |
| Self-modifying code (SMC) | VMP outer packer stub decrypts `.text` and calls `VirtualProtect` (2.x) or `ZwProtectVirtualMemory` (3.x); Themida's "Advanced Virtualization" and Denuvo runtime patches use finer-grained SMC that decrypts a few bytes just before execution and re-encrypts after. | Debray & Coogan (CGO 2009), PackHero (arXiv 2506.00659), 0xrafasec's x64dbg scriptable-BP workflow |
| TLS-callback bootstrap | Themida and VMP set anti-debug up via TLS callbacks that run before AddressOfEntryPoint. Our detector reads bytes at EP but never inspects `IMAGE_DIRECTORY_ENTRY_TLS`. | RingZero Labs "Analyzing TLS Callbacks" |
| Anti-debug catalogue | `VMProtectIsDebuggerPresent` and `VMProtectIsValidImageCryptHash` are shipped in every real VMP-protected commercial sample. Our tool has zero anti-debug detection. | al-khaser, Check Point anti-debug.checkpoint.com, Unprotect Project |
| Anti-disassembly (jmp+1, overlapping insns, SEH-based garbage) | VMP vmenter frequently contains overlapping-instruction shellcode; Themida uses aggressive SEH tricks | IEEE 6707878, USTC anti-disas.pdf |
| String encryption / crypto stubs (RC4, AES, XOR loops) | Common in Themida (section encryption) and in modern VMP builds with "String Protection" option on; findcrypt-yara / signsrch signatures for AES S-boxes, SHA IV, Rcon constants | findcrypt-yara, Practical Malware Analysis Ch. 13 |
| API hashing (ROR13, CRC32, MurmurHash, djb2) | PEB-walk + hash-lookup replaces IAT; `mov reg, gs:[60h]` (x64) or `fs:[30h]` (x86) followed by `ror ??, 0Dh` inside export-directory loop | MITRE T1027.007, Cytomate PEB walk write-up |

---

## 6. Mutation / signature-fragility gaps

Sources: research reports on mutators-and-metamorphism + our own matcher inventory.

### 6.1 Which current matchers break under mutation

| Matcher | File:line | Fragility | Why |
|---|---|---|---|
| `EntryStubMatcher::PUSHAD` (`0x60`) | `version_matchers.rs:25` | 🟡 Structural | 1-byte opcode; robust as long as VMP1 keeps `pushad` at the very start. VMP 3.x uses variable prelude → matcher won't fire (correctly — it's a VMP1 matcher). |
| `EntryStubMatcher::MOV_ESI_IMM32` (`0xBE ? ? ? ?`) | `version_matchers.rs:27` | 🔴 Fragile | Register-specific (`0xBE` = `mov esi, imm32`). If a VMP1 build were re-emitted with EDI-as-scratch instead of ESI, the matcher misses. |
| `EntryStubMatcher::LEA_EDI_ESI_DISP32` (`0x8D 0xBE ? ? ? ?`) | `version_matchers.rs:29` | 🔴 Fragile | Encodes both source and dest registers. |
| `EntryStubMatcher::PUSH_IMM32` (`0x68 ? ? ? ?`) | `version_matchers.rs:31` | 🟢 Structural | Any 32-bit push immediate — mutation-tolerant. |
| `EntryStubMatcher::CALL_REL32` / `JMP_REL32` | `version_matchers.rs:33-35` | 🟢 Structural | Same. |
| `EntryStubMatcher::find_push_call_jmp` (target lands in `.vmpN`) | `version.rs:146-198` | 🟡 Structural | Target-section resolution is robust; but requires literal `.vmp0` / `.vmp1` names — renaming defeats it. |
| `SemanticMatcher::is_indirect_at` (opcode + mod=00 rm≠4,5) | `handler_semantic.rs:189-201` | 🟢 Structural | ModR/M-shape check, not byte-exact; junk-tolerant. |
| `SemanticMatcher::is_disp_at` (opcode + mod=01 or mod=10) | `handler_semantic.rs:204-215` | 🟢 Structural | Same. |
| `SemanticMatcher::is_push_shape` / `is_pop_shape` / `is_vjmp_shape` (composed presence-anywhere checks) | `handler_semantic.rs:338-352` | 🔴 Fragile-on-junk | The three predicates check *any occurrence* within the handler body — a junk `mov r,[r]` inserted by VMP's mutator satisfies `has_load_indirect` even if the real load is not there. |
| `is_nand_shape` / `is_nor_shape` (2+ NOTs + AND/OR reg-reg) | `handler_semantic.rs:330-336` | 🟡 Semi-structural | Junk NOTs (impossible on architectural state but present in dead code) would inflate the NOT count. Junk-code stripping needed before matching. |
| `is_vmexit` (POPFQ/POPAD then RET within 32 bytes) | `handler_semantic.rs:318-328` | 🔴 Fragile-window | The 32-byte window was picked arbitrarily; VMP 3.x can insert enough junk between POPFQ and RET to blow past 32 bytes. Also matches any code with a `0x9D` immediate byte incidentally near a `0xC3`. |
| `XorKeyAnalyzer::XorPattern` (`REX 35` and `REX 81 F0` prefixes for x64 XOR-imm32) | `xor_key_analyzer.rs:31-36` | 🔴 Very fragile | VMP 3.x uses randomised inverse ops in the FDJ tail (not just XOR); the current matcher will miss many builds. Rolls in v3.6+ mixed neg/rot/inc are documented in Zakocs and back.engineering. |
| `DispatchTableLocator::find_dispatch_pattern` (256 consecutive pointers in `[image_base, image_base + 2GB)`) | `dispatch_table.rs:76-143` | 🔴 Model-mismatch | VMP 3.x has no dispatch table (threaded dispatch, per §4.1). Even for 2.x, the 256-pointer assumption fails on merged-handler 3.7+ builds. Also produces false positives on any pointer-heavy `.rdata` (e.g. vtables). |
| VMProtect literal-string marker | `version.rs:202-204` | 🟢 Reliable when present | Can be stripped by `--strip-file-name` builds but almost never is. |
| Handler `analyze_bytecode` first-byte + ModR/M peek | `handler_classifier.rs:92-252` | 🔴 Fragile | Only looks at bytecode[0] (with 1-byte lookahead for `0x48` REX / `0xFF` group / `0xC7`), ignores REX+opcode+ModR/M combinations. Real VMP handlers have wider prologues. |

### 6.2 Normalisation passes that would restore signature reliability

Ranked by how many downstream matchers each pass would rescue.

| Pass | Rescues | Effort |
|---|---|---|
| Junk-code stripper (peephole + backward liveness) | All 8 `is_*_shape` matchers in `handler_semantic.rs`; `is_vmexit` window check; `analyze_bytecode` first-byte match | 2-3 days for a first cut |
| Register-role canonicaliser (data-flow assignment of VIP/VSP/KEY roles to virtual regs) | Enables cross-instance VMP 3.x matcher stability; prerequisite for any real lifter | 4-8 days |
| Block-canonical ordering (fold trampoline chains, DCE) | Themida trampolines; VMP 3.x junk BBs between handlers | 3-5 days |
| Opaque-predicate solver (linear identities) | OLLVM `-bcf`, VMP mutator OPs | 2-4 days |
| MBA collapse (linear, semi-linear) | VMP 3.x flag computations, Tigress EncodeArithmetic | 4-6 days (reuse msynth-style synthesis) |
| Structural VMP-2/3 dispatcher fingerprint (three-instruction chain match with tolerated gaps) | Section-name-scrubbed VMP hosts (BattlEye, EAC, custom) | 1-2 days |

**Design principle from the research** (nac-l, back.engineering, Thalium, hackyboiz all converge on this): lift to an IR (VTIL for GPL-3.0-tolerant projects, LLVM IR otherwise), run the optimiser, then match on semantic invariants (stack delta, VIP delta, VSP delta, memory-footprint) — not on bytes. Our current pipeline stops at byte-window matching; the state-of-the-art moved past this around 2020.

---

## 7. Prioritised roadmap

Ordered by impact / effort ratio. Effort buckets: **S** <4h, **M** 4-16h, **L** 16-80h, **XL** 80h+.

| # | Priority | Item | Unlocks | Effort | Driven by |
|---|---|---|---|---|---|
| 1 | P0 | Add class-level "some protector" gate (entropy / W+X / stripped-IAT / EP-outside-`.text` / overlay) with a `RuleScore`-style aggregator | Truthful classification on section-renamed VMP, Themida, and unknown packers instead of `Unknown`(0) | M | §2.2 |
| 2 | P0 | Add cheap vendor byte-table + section-name matchers for Themida, Enigma, Obsidium, Code Virtualizer, Armadillo, ASPack, Compressor tier | 8-10 new families detected with no new abstraction | M | §2.1 |
| 3 | P0 | Add VMP-version string markers (`ZwProtectVirtualMemory` → 3.x, `VBoxRev/VBoxVer` → VMP anti-VM) | Cheaper version discrimination on existing VMP path | S | §2.1 |
| 4 | P0 | Implement the 8 P0 VMP semantic matchers (`Add`, `Ret`, `Ldd`, `Str`, `Vsetvsp`, `PushImm`/`PushReg` split, `Popreg`, `Popf`) | Covers most-frequent handlers in a real virtualised function; unblocks meaningful lift on any VMP sample | L | §3.1 |
| 5 | P1 | Junk-code stripper pass (liveness + peephole) run before `SemanticMatcher::classify` | Rescues all `is_*_shape` matchers against VMP 3.x mutator envelope; a prerequisite for handler-level lifting on modern builds | L | §5, §6.2 |
| 6 | P1 | ~~Structural VMP dispatcher fingerprint (three-instruction chain `mov r,[VIP]; xor r,key; add r,tbl; jmp [r]` with gap tolerance) alongside section-name lookup~~ **IMPLEMENTED** (Commit I: `protector_matchers::has_{mov_indirect_load,xor_reg_imm,add_reg_mem,indirect_jmp_ff4}` + `protector_signals::scan_rx_sections_for_dispatcher`, +45 pts in `ProtectorDetector`) | Detects BattlEye BEDaisy, EAC-in-scrubbed-section, renamed-section VMP; converts §4.1 model-mismatch into false-negative-free | L | §2.3, §4.1 |
| 7 | P2 | Register-role canonicaliser (data-flow assignment of VIP/VSP/VKEY/handler-base) | Prerequisite for any lifter emitting IR from VMP 3.x; also stabilises matchers against per-instance register randomisation | XL | §5, §6.2 |
| 8 | P2 | VMP operand-crypto per-version replacement of `crc*31 + val` placeholder — starting with VMP 2.x rolling arithmetic chain (documented) | Real operand values in devirtualised output instead of placeholder-decrypted noise | L | §4.2 |
| 9 | P2 | Real-sample corpus (5-10 VMP-3 hello-world builds, VMProtect Free/Trial) — closes AUDIT_REPORT §Days 6-7 which is blocking every "true positive rate" claim. **Real-sample harness implemented** (`tests/samples.rs`, gated behind `--features real-samples`, walks `tests/fixtures/<vmpN>/`, checks family/version/dispatch-table against `assert_cmd` runs). **Synthetic-sample harness ALSO implemented (Commit S)** — `src/synthetic_sample.rs` emits VMP-shaped PEs (correct section layout, entry stub, structural dispatcher fingerprint, 256-entry dispatch table, 30 handler shells with byte-perfect matches for 11 semantic categories) that the CLI's own detection stack, register-role voter and semantic classifier must all agree on end-to-end (`tests/synthetic.rs`, gated behind `--features synthetic-samples`). The synthetic path closes a major "can we even verify our own pipeline" gap without waiting for the real corpus — every P0/P1 above is now verifiable against a controlled ground-truth today. The real-sample verification remains open until user-provided binaries land in `tests/fixtures/<vmpN>/`. | Every P0/P1 above becomes verifiable rather than aspirational | M (once samples are available) | §Q2 in AUDIT_REPORT |
| 10 | P3 | Import-table restoration (permissive-license path; behaviour of vmpfix / VMPImportFixer as reference) | End-to-end devirtualised output with real call targets instead of raw pointers | XL | §5 |

---

## 8. Sources

Cumulative bibliography from all six research agents, deduplicated. GPL-3.0 code is reference-only per project rules.

### 8.1 Vendor documentation
- Oreans Themida VM overview — https://www.oreans.com/help/tm/hm_virtual-machine.htm
- Oreans Themida macros — https://oreans.com/help/tm/hm_which-macros-should-i-use_.htm
- Oreans Themida — https://www.oreans.com/Themida.php
- Oreans Themida PDF — https://www.oreans.com/ThemidaHelp.pdf
- Oreans Code Virtualizer — https://www.oreans.com/help/cv/hm_how-code-virtualizer-works.htm
- VMPSoft news / changelog — https://vmpsoft.com/news/
- Enigma Protector — https://enigmaprotector.com/
- Enigma Protector manual — https://enigmaprotector.com/assets/files/manual_en.pdf
- Enigma Protector forum "trick protection analyzers" — http://forum.enigmaprotector.com/viewtopic.php?f=7&t=565
- Obsidium — https://www.obsidium.de/show/details/en
- SafEngine — https://www.safengine.com/en-us/products/protector
- ExeCryptor / SoftComplete — https://execryptor.en.download.it/
- Irdeto Denuvo Anti-Tamper — https://irdeto.com/video-games/denuvo-anti-cheat/anti-tamper
- Riot Games — Vanguard On-Demand — https://www.riotgames.com/en/news/vanguard-on-demand

### 8.2 Community writeups
- Rolf Rolles VMProtect Part 0 — https://www.msreverseengineering.com/blog/2014/6/23/vmprotect-part-0-basics
- back.engineering VMProtect 2 detailed analysis — https://back.engineering/blog/17/05/2021/
- blog.back.engineering VMP2 Part Two — https://blog.back.engineering/21/06/2021/
- back.engineering Themida static devirt — https://back.engineering/blog/09/05/2026/
- Mitchell Zakocs VMProtect 3 — https://www.mitchellzakocs.com/blog/vmprotect3
- r0da VMP 3.x quick look — https://whereisr0da.github.io/blog/posts/2021-01-05-vmp-1/
- r0da VMP 3.x Part 2 — code mutation — https://whereisr0da.github.io/blog/posts/2021-01-26-vmp-2/
- r0da VMP 3.x Part 3 — virtualization — https://whereisr0da.github.io/blog/posts/2021-02-16-vmp-3/
- cyber.wtf Defeating VMProtect's latest tricks — https://cyber.wtf/2023/02/09/defeating-vmprotects-latest-tricks/
- hackyboiz VMP devirt Part 1 (LLVM) — https://hackyboiz.github.io/2025/09/11/banda/LLVM_based_VMP/en/
- hackyboiz VMP devirt Part 2 — https://hackyboiz.github.io/2025/12/11/banda/VMPpart2/en/
- vxcall VMProtect 3.8.1 — https://vxcall.github.io/posts/vmprotect-research/
- nac-l Lifting Binaries Part 0 — https://nac-l.github.io/2025/01/25/lifting_0.html
- 0xnobody Devirt intro — https://0xnobody.github.io/devirtualization-intro/
- Thalium LLVM-powered devirt — https://blog.thalium.re/posts/llvm-powered-devirtualization/
- Quarkslab Deobf of OLLVM — https://blog.quarkslab.com/deobfuscation-recovering-an-ollvm-protected-program.html
- Quarkslab Obfuscation vs the Optimizer — https://blog.quarkslab.com/obfuscation-vs-the-optimizer-an-llvm-middle-end-arms-race.html
- RPISEC Dissecting LLVM Obfuscator Part 1 — https://rpis.ec/blog/dissection-llvm-obfuscator-p1/
- Themida x86 2.3.5.10 anti-debug — https://medium.com/@reversing/analysis-of-oreans-themida-x86-version-2-3-5-10-anti-debugger-detections-8328ebd858c8
- Sachiel Anti-debug in VMProtect — https://sachiel-archangel.medium.com/anti-debug-techniques-of-vmprotect-f1e343ee0fb2
- Connor-Jay Dunn Denuvo Analysis — https://connorjaydunn.github.io/blog/posts/denuvo-analysis/
- HackMag Denuvo War Stories — https://hackmag.com/security/denuvo
- momo5502 Reverse Engineering Denuvo in Hogwarts Legacy — https://momo5502.com/posts/2025-10-03-reverse-engineering-denuvo-in-hogwarts-legacy/
- 0xPacman DenuvOwO Hypervisor Report — https://github.com/0xPacman/RE-Reports/blob/main/DenuvOwO_Hypervisor_Report.md
- TechSpot hypervisor Denuvo bypasses (2024) — https://www.techspot.com/news/111897-hypervisor-based-cracks-breaking-denuvo-protections-hours.html
- Hypercall Inside anti-cheat EasyAntiCheat Part 1 — https://hypercall.net/posts/EasyAntiCheat-Part1/
- Hypercall Inside anti-cheat Packman — https://hypercall.net/posts/Packman/
- s4dbrd Reversing BEDaisy.sys — https://s4dbrd.github.io/posts/reversing-bedaisy/
- Xyrem Engineering Valorant Guarded Regions — https://reversing.info/posts/guardedregions/
- Archie Vanguard dispatch-table hooks — https://archie-osu.github.io/2025/04/11/vanguard-research.html
- gmh5225 vgk.sys analysis — https://gist.github.com/gmh5225/2b430b6025c8888196dd95c8557bfc6f
- Andrea Allievi Anti-cheat evolution in Windows 11 — https://www.andrea-allievi.com/blog/new-year-post-anti-cheat-evolution-in-windows-11/
- mrphrazer Automated Detection of Obfuscated Code — https://synthesis.to/2021/08/10/obfuscation_detection.html
- Emproof / mrphrazer obfuscation_detection plugin — https://github.com/mrphrazer/obfuscation_detection
- Osanda NtGlobalFlag — https://osandamalith.com/2016/04/23/debugger-detection-using-ntglobalflag/
- Unprotect Project — VMProtect — https://unprotect.it/technique/vmprotect/
- Unprotect Project — Themida — https://unprotect.it/technique/themida/
- Unprotect Project — Obsidium — https://unprotect.it/technique/obsidium/
- Unprotect Project — Debug Registers — https://unprotect.it/technique/debug-registers-hardware-breakpoints/
- Check Point Anti-Debug — https://anti-debug.checkpoint.com/techniques/debug-flags.html
- al-khaser Anti-Debug wiki — https://github.com/LordNoteworthy/al-khaser/wiki/Anti-Debugging-Tricks
- Cytomate PEB walk — https://cytomate.medium.com/peb-walk-avoid-api-calls-inspection-in-iat-by-analyst-and-bypass-static-detection-of-av-edr-ee7b0dd9c33c
- Hexacorn PE Section names revisited — https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
- RingZero Labs Analyzing TLS Callbacks — https://www.ringzerolabs.com/2019/08/analyzing-tls-callbacks.html
- 0xrafasec Defeating SMC in VMP with x64dbg — https://0xrafasec.com/en/posts/defeating-self-modifying-code-in-vm-protected-binaries-a-practical-unpacking-workflow-with-x64dbg-scriptable-breakpoints
- yoshlsec Manually Unpacking UPX — https://yoshlsec.github.io/manuallyupx/
- GreatBinary Unpacking UPX-packed binaries — https://greatbinary.win/article/unpacking-upx-packed-binaries/
- assarbad VMP resource gist — https://gist.github.com/assarbad/83e7def48a986727b12fcc644da1aa57
- Trail of Bits Simplifying MBA with CoBRA — https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/
- Oracle Labs Constant Blinding on GraalVM — https://labs.oracle.com/pls/apex/f?p=94065:10:5008820964003:8269
- DeepWiki OLLVM CFF — https://deepwiki.com/eshard/obfuscator-llvm/4.1-control-flow-flattening
- DeepWiki Hikari — https://deepwiki.com/HikariObfuscator/Hikari/3-obfuscation-techniques
- DeepWiki Tigress — https://deepwiki.com/tum-i4/obfuscation-benchmarks/4.1-tigress-obfuscator
- Wikipedia Denuvo — https://en.wikipedia.org/wiki/Denuvo
- Wikipedia Anti-tamper software — https://en.wikipedia.org/wiki/Anti-tamper_software

### 8.3 Academic papers
- Salwan / Bardin / Potet — Symbolic Deobfuscation (DIMVA 2018) — https://shell-storm.org/talks/DIMVA2018-deobfuscation-salwan-bardin-potet.pdf
- Blazytko et al. — Syntia (USENIX 2017) — https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-blazytko.pdf
- Guinet et al. — QSynth (BAR 2020) — https://www.ndss-symposium.org/wp-content/uploads/2020/04/bar2020-23009.pdf
- SoK Automatic Deobfuscation of Virtualization-protected Applications (ARES 2021) — https://eprints.cs.univie.ac.at/7012/1/3465481.3465772.pdf
- Li et al. — Chosen-Instruction Attack (NDSS 2022) — https://www.ndss-symposium.org/wp-content/uploads/2022-15-paper.pdf
- Schloegel et al. — Loki (USENIX 2022) — https://publications.cispa.saarland/3590/1/USENIX22-Loki.pdf
- ProMBA (CCS 2023) — https://psl.hanyang.ac.kr/assets/pdf/ccs23.pdf
- Devmp (Internetware 2025) — https://dl.acm.org/doi/10.1145/3755881.3755892
- CMC 2025 Advancing Code Obfuscation vs DSE — https://cdn.techscience.cn/files/cmc/2025/TSP_CMC-84-1/TSP_CMC_62743/TSP_CMC_62743.pdf
- Defeating Opaque Predicates Statically (arXiv 1909.01640) — https://ar5iv.labs.arxiv.org/html/1909.01640
- Heuristic Approach to Detect Opaque Predicates (BAR 2020) — https://www.ndss-symposium.org/wp-content/uploads/2020/04/bar2020-23004.pdf
- Inspecting Compiler Optimizations on MBA (BAR 2025) — https://www.ndss-symposium.org/wp-content/uploads/bar2025-final7.pdf
- MBA-Blast (USENIX 2021) — https://www.usenix.org/conference/usenixsecurity21/presentation/liu-binbin
- Cheng et al. — BinUnpack (USENIX Sec 2021) — https://www.usenix.org/system/files/sec21-cheng-binlin.pdf
- Junod et al. — OLLVM (SPRO 2015) — https://crypto.junod.info/spro15.pdf
- Kalnai & Poslušný — Rich header anomaly detection (VB2019) — https://www.virusbulletin.com/uploads/pdf/magazine/2019/VB2019-Kalnai-Poslusny.pdf
- Ferrie — Anti-unpacker tricks — https://pferrie.tripod.com/papers/unpackers.pdf
- Debray & Coogan — Reverse Engineering Self-Modifying Code (CGO 2009) — https://www2.cs.arizona.edu/people/debray/Publications/unpacker-extraction.pdf
- PackHero (arXiv 2506.00659) — https://arxiv.org/pdf/2506.00659
- Larsen et al. — Software Diversification (Oakland 2014) — https://oaklandsok.github.io/papers/larsen2014.pdf
- Brezinski (Wiley 2023) — Metamorphic Malware and Obfuscation — https://onlinelibrary.wiley.com/doi/10.1155/2023/8227751
- Stanford CS155 Evolution of Code — https://crypto.stanford.edu/cs155old/cs155-spring10/papers/viruses.pdf
- Nguyen Minh Hai — Packer identification (SSPREW17) — http://www.jaist.ac.jp/~mizuhito/papers/conference/SSPREW17.pdf
- UnSafengine64 (2024) — https://www.researchgate.net/publication/377820331_UnSafengine64
- Arxiv 2408.00500 — If It Looks Like a Rootkit and Deceives Like a Rootkit — https://arxiv.org/html/2408.00500v1
- IEEE 6707878 — Instruction overlapping — https://ieeexplore.ieee.org/document/6707878/
- USTC anti-disas — http://staff.ustc.edu.cn/~bjhua/courses/security/2014/readings/anti-disas.pdf
- Wu / opaque predicates — https://faculty.ist.psu.edu/wu/papers/opaque-isc16.pdf
- eprint.iacr.org 2017/787 — https://eprint.iacr.org/2017/787.pdf
- ACM TOSEM sem2vec — https://dl.acm.org/doi/10.1145/3569933

### 8.4 Open-source tools

Permissive-licence (safe to study *and* to include as dependencies where the licence matches; check per project):
- Detect It Easy (MIT) — https://github.com/horsicq/Detect-It-Easy
- DiE library — https://github.com/horsicq/die_library
- die-python — https://github.com/elastic/die-python
- Neo23x0 signature-base (DRL 1.1, attribution) — https://github.com/Neo23x0/signature-base
- CAPA rules (Apache 2.0) — https://github.com/mandiant/capa-rules
- ditekshen/detection — https://github.com/ditekshen/detection
- godaddy/yara-rules (archived) — https://github.com/godaddy/yara-rules/blob/master/packers/vmprotect.yara
- PEiD packerid — https://github.com/sooshie/packerid
- PE-LiteScan — https://github.com/DosX-dev/PE-LiteScan
- REMINDer — https://github.com/packing-box/reminder
- Awesome executable packing — https://github.com/packing-box/awesome-executable-packing
- Triton — https://triton-library.github.io/
- Miasm (GPLv2 — reference only) — https://github.com/cea-sec/miasm
- Sibyl — https://github.com/cea-sec/Sibyl
- Souper (Apache 2.0) — https://github.com/google/souper
- msynth — https://github.com/mrphrazer/msynth
- Syntia — https://github.com/RUB-SysSec/syntia
- unlicense (Themida) — https://github.com/ergrelet/unlicense
- themida-unmutate — https://github.com/ergrelet/themida-unmutate
- themida-unmutate Binary Ninja plugin — https://github.com/ergrelet/themida-unmutate-bn
- angr — https://github.com/angr/angr
- vmpfix (import fix) — https://github.com/archercreat/vmpfix
- VMPImportFixer — https://github.com/mike1k/VMPImportFixer
- birosca (VMP 1.x unpacker) — https://github.com/keowu/birosca
- Titan (Triton-based VMP devirt) — https://github.com/Brugarolas/titan
- Mergen (LLVM VMP devirt) — https://github.com/NaC-L/Mergen
- omill (Remill-based) — https://github.com/binsnake/omill
- Tigress protection (Salwan) — https://github.com/JonathanSalwan/Tigress_protection
- Themida-Research (stuxnet147) — https://github.com/stuxnet147/Themida-Research
- Denuvo hypervisor crack audit (RD945) — https://github.com/RD945/hypervisor-crack-audit
- BattlEye/EAC unpacking guide — https://github.com/zodiacddos/BattleEye-EasyAntiCheat-Bypasses
- Vanguard trace (armvirus) — https://github.com/armvirus/VanguardTrace

GPL-3.0 — reference / behaviour only per project rules (`CLAUDE.md`):
- vmpattack — https://github.com/0xnobody/vmpattack
- NoVmp — https://github.com/can1357/NoVmp
- vmpdump — https://github.com/0xnobody/vmpdump
- vmp2 / vmprofiler / vmdevirt (back.engineering) — https://github.com/backengineering/vmp2 · https://git.back.engineering/vmp2/vmprofiler-cli · https://git.back.engineering/vmp2/vmdevirt
- themida-devirt (back.engineering) — https://github.com/backengineering/themida-devirt
- VTIL — https://github.com/vtil-project/VTIL-Core
- vmhook (backengineering EAC VMP2 handler indexes) — https://github.com/backengineering/vmhook
- VMProtect-devirtualization (Salwan) — https://github.com/JonathanSalwan/VMProtect-devirtualization
- HikariObfuscator wiki — https://github.com/HikariObfuscator/Hikari/wiki/AntiClassDump
- OLLVM wiki features — https://github.com/obfuscator-llvm/obfuscator/wiki/features · https://github.com/obfuscator-llvm/obfuscator/wiki/Control-Flow-Flattening
- MODeflattener — https://github.com/mrT4ntr4/MODeflattener
- RPISEC llvm-deobfuscator — https://github.com/RPISEC/llvm-deobfuscator
- pakt/decv (Code Virtualizer decompiler) — https://github.com/pakt/decv
