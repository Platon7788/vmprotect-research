# VMP 3.5+ Reverse Engineering Research

> **VMProtect 3.5+ complete internal architecture analysis.**
> From PE structure to bytecode interpreter — 855+ lines of documented research.

## Overview

This repository contains the most comprehensive public documentation of **VMProtect 3.5+** internal architecture, based on extensive reverse engineering of real-world VMP-protected binaries (Loader.exe, Memory.dll, Check.exe from a Metin2 cheat suite).

## What's Inside

### Documentation

- **VMP_INTERNALS.md** (855 lines) — Complete architecture:
  - PE structure (`.vmp0`, `.vmp1` sections)
  - Two dispatch models: **context-table** (Loader.exe) and **VEH-based** (Memory.dll)
  - Bytecode encryption (rolling XOR cipher + x86 decoder)
  - Complete VM instruction set (22 opcodes)
  - Handler dispatch mechanism
  - Heap trampoline + context structure
  - Concrete trace analysis from live execution
  - Full devirtualization approaches (static, dynamic, hybrid)
  - Tool ecosystem analysis (NoVmp, vmp2, VMAttack, SATURN, TritonDSE)

- **TOOLING_FIXES.md** — Build recipes for all tools on modern systems (GCC 16, LLVM 22, CMake 4)

### Tools

- `tools/vmp_interp.py` — VMP bytecode interpreter skeleton with 18/22 opcodes
- `tools/triton_veh_handler.py` — Triton-based VEH handler for intercepting VMP dispatch
- `tools/reconstruct_memory.py` — Runtime PE reconstruction from memory dumps

### Key Discoveries

| Discovery | Description |
|-----------|-------------|
| **VEH-based dispatch** | VMP 3.5+ uses Vectored Exception Handling for bytecode dispatch, NOT page faults |
| **Two dispatch models** | Context-table (older) vs VEH-based (newer) |
| **Hybrid functions** | Normal x86 functions with embedded VMP CALLs |
| **Heap trampolines** | Dispatch goes through heap-allocated trampoline code |
| **NoVmp incompatibility** | VMP 3.5+ entry stubs self-modify, breaking NoVmp's assumptions |
| **Encrypted bytecodes** | Rolling XOR with binary-specific x86 decoder sequences |

## Files

| File | Description |
|------|-------------|
| `VMP_INTERNALS.md` | Complete architecture documentation |
| `TOOLING_FIXES.md` | Build fixes for all tools |
| `tools/vmp_interp.py` | VMP bytecode interpreter |
| `tools/triton_veh_handler.py` | Triton VEH hook for Memory.dll |
| `tools/reconstruct_memory.py` | PE reconstruction script |

## Requirements

To replicate this research:
- Linux with Wine 11.9+ (wine-staging recommended)
- Python 3 with capstone, triton libraries
- NoVmp (can1357) — built with Clang + system capstone
- GDB + rr (for execution tracing)
- Frida (optional, for live hooking)

## Related Projects

- [NoVmp](https://github.com/can1357/NoVmp) — Static devirtualizer for VMP 2.x-3.0
- [NoVmpy](https://github.com/wallds/NoVmpy) — Python VTIL-based VMP analysis
- [VMProtect-devirtualization](https://github.com/JonathanSalwan/VMProtect-devirtualization) — Dynamic Triton-based approach
- [vmp2](https://github.com/backengineering/vmp2) — VMP2 analysis toolkit (archived)
- [VMAttack](https://github.com/anatolikalysch/VMAttack) — IDA plugin for VM analysis
- [VTIL](https://github.com/vtil-project/VTIL-Core) — Devirtualization IR framework
- [Triton](https://github.com/JonathanSalwan/Triton) — Dynamic symbolic execution
- [SATURN](https://arxiv.org/abs/1909.01752) — LLVM-based deobfuscation
- [TritonDSE](https://github.com/quarkslab/tritondse) — High-level symbolic exploration

## License

MIT — Use freely, cite if you build on this research.
