# VMP (VMProtect) 3.5+ Internal Architecture

> Compiled from live RE session: NoVmp source analysis, NoVmpy Python source,
> Triton symbolic execution traces, runtime memory dump reconstruction,
> and manual PE analysis.

---

## 1. PE Structure (VMP-Protected Binary)

A VMP-protected PE contains these key sections:

| Section | Content | Typical | Notes |
|---------|---------|---------|-------|
| `.text` | Original code stubs (CALL to VM) | Encrypted at file level, decrypted at runtime | In VMP 3.5+ dumps, often present as real x86 code |
| `.vmp0` | VM entry stubs + handler dispatch tables | Encrypted, raw=0x0 (no file data) | Decrypted at runtime from `.vmp1` |
| `.vmp1` | VM bytecode + handler code | Encrypted in file, large (5-6MB) | Contains both handler x86 code and VM instruction stream |
| `.rdata` | Import tables, strings | Often zeroed by VMP | |
| `.data` | Runtime data | Usually present | |
| `.pdata` | Exception handlers | Present | |

**Key observation:** `.vmp0` has `raw=0x0` in the PE file — its content is decrypted from `.vmp1` at runtime. Static PE readers see an empty section.

---

## 2. VMP Entry Mechanism

### Pre-3.5 (Classic)

```
.text:    CALL <target_in_.vmp0>
.vmp0:    68 xx xx xx xx    PUSH <encrypted_vip>     ; VM instruction pointer (encrypted)
          E8 yy yy yy yy    CALL <VM_dispatcher>     ; Enter VM dispatch loop
```

- `0x68` at target = PUSH immediate (the encrypted initial VIP)
- `0xE8` at target+5 = CALL to VM dispatcher
- NoVmp's `parse_vmenter()` asserts exactly this pattern: `fassert( is[0].is(PUSH, {IMM}) )`

### 3.x (Context Table Dispatch — Loader.exe style)

**At file level (pre-execution):** Same as classic pattern (PUSH + CALL)
**After first execution (self-modified):**

```
.text:    CALL <target_in_.vmp0>
.vmp0:    90                NOP                     ; Was 0x68 (PUSH opcode)
          5B                POP RBX                  ; Gets return addr = key
          E9 zz zz zz zz    JMP <VM_dispatcher>     ; vs CALL in classic
```

The `POP RBX` pops the return address pushed by the outer `.text` CALL. This return address is used as part of key derivation instead of the PUSH immediate.

**Why self-modify?** Anti-static-analysis. Even with a memory dump, the entry stubs are modified and the original encrypted VIP is lost.

### Dispatch Flow (Context Table — Traced via Triton)

```
Entry stub (.vmp0):
  NOP (alignment)
  POP RBX (gets return addr from outer CALL = entry_va+10)
  JMP → dispatcher

Dispatcher (.vmp1):
  XCHG [RSP], RBX
  PUSH RBX
  MOVSX EBX, SP          ; stack-related computation
  MOVZX BX, R15B         ; low byte of R15 (usually 0)
  BSWAP EBX              ; byte swap
  LEA RBX, [RIP + offset] ; compute table base
  MOV RBX, [RBX + off]    ; LOAD CONTEXT POINTER from table
  LEA RBX, [RBX + const]  ; add base to context
  XCHG [RSP], RBX         ; context pointer → stack
  RET                     ; "return" → context pointer address
```

**Critical:** The `MOV RBX, [RBX + offset]` reads a **VM context pointer** from a table in `.vmp0`. This context is a heap-allocated structure containing the VM's state (instruction pointer, stack pointer, encryption key, register file).

### Context Table

Located at a fixed offset within `.vmp0` (e.g., `.vmp0+0x1D4010` in Loader.exe).

Contains pointers to `VM_CONTEXT` structures on the process heap:

```
.vmp0+0x1D4010: 0x00006fffece5cd1e  (Wine heap address)
.vmp0+0x1D4018: another context ptr
...
```

These pointers are **dynamically allocated** at VMP initialization and vary per run. They contain:
- Encrypted VIP (current bytecode position)
- VSP (virtual stack pointer)
- Rolling XOR key
- Saved x86 registers (15 GP registers + flags)
- Handler dispatch table base

### 3.5+ VEH-Based Dispatch (Memory.dll style — OUR BREAKTHROUGH)

Memory.dll exports like `ReadByte` are **hybrid functions** — normal x86 functions that call into VMP internally:

```
ReadByte (RVA 0x1560):
  push rbx            ; normal x86 prologue
  push rbp
  push rsi
  sub rsp, 0x50
  mov rax, [rip + ...]; security cookie
  xor rax, rsp
  ...
  mov ecx, 0x18       ; ← VM entry key (pushed before call)
  push rcx
  call 0xD1FE2        ; ← CALL to .vmp0 (bytecode, NOT x86!)
  ...
  test rax, rax
  jne error
  ...
  ret
```

**Key discovery:** The `call 0xD1FE2` goes to an address in `.vmp0` where the bytes are **VM bytecode, not x86 code**:
```
.vmp0+0x59FE2: 13 fb 66 bc 2b 30 b1 3d...  (garbage as x86)
```

This works because **VMP 3.5+ uses Vectored Exception Handler (VEH)-based dispatch:**

1. `.vmp0` is mapped as PAGE_NOACCESS (or guard page)
2. Normal x86 function pushes VM key and `CALL`s to `.vmp0`
3. The CALL triggers a **page fault** (since `.vmp0` is no-access)
4. VMP's registered VEH catches the exception
5. VEH reads the faulting address = determines which VM function to execute
6. VEH reads the VM key (0x18) from the stack = identifies the entry point
7. VEH fetches and decrypts VM bytecodes using rolling XOR cipher
8. VEH dispatches to handler code in `.vmp1`
9. After execution, VEH modifies the thread CONTEXT to resume at the instruction after the CALL
10. Normal x86 epilogue runs, returns result

**Evidence for VEH dispatch:**
- `.vmp0` has `PAGE_NOACCESS` characteristics in PE (not executable!)
- CALL target bytes are garbage as x86 — they're VM bytecodes
- No self-modification (pre/post call bytes identical)
- Import table and export table both hidden (SIZE=0 in data dirs)
- VMP's initialization registers a VEH (can be confirmed via `RtlAddVectoredExceptionHandler`)
- Data directory entries for `.pdata` suggest SEH-aware compilation

**This is fundamentally different from Loader.exe's context-table approach.** Memory.dll uses a cleaner, more modern VMP architecture where:
- `.text` contains normal compiled functions with embedded VMP calls
- `.vmp0` is bytecode + page fault trigger
- `.vmp1` contains handler code
- No context table lookup needed — bytecodes are self-contained
- No self-modification — stubs remain intact

---

## 3. VM Bytecode Format

### Encryption (Rolling XOR Cipher)

```
decrypted_byte = encrypted_byte XOR key
key ^= decrypted_byte
```

- Key starts as the encrypted VIP (from the PUSH immediate in pre-3.5, or derived from return address in 3.5+)
- Each byte is XOR'd with current key
- After decrypting, key is XOR'd with decrypted byte (key evolves through stream)
- This is a self-synchronizing stream cipher

### From NoVmpy `decode_emu()` in `vm.py`:

```python
def decode_emu(self, decoder, ct, reg, size):
    mask = get_mask(size*8)
    pt = ct & mask
    for insn in decoder:
        # Track how the key register is modified
        # XOR, ADD, SUB, NOT, NEG, BSWAP, ROL, ROR on the key
        # Each handler modifies the key according to its x86 implementation
    return pt  # decrypted value
```

### Instruction Encoding

Each VM instruction is a bytecode stream (variable length, usually 1-3 bytes):

```
Byte 0:   Opcode (encrypted)
Byte 1+:  Operands (encrypted)
```

**From NoVmpy `handler.py` — VM instruction types:**

| Opcode ID | Name | Description | Operands |
|-----------|------|-------------|----------|
| VM_INS_NOP | nop | No operation | None |
| VM_INS_PUSH_REG | push_reg | Push virtual register | 1 byte: register index |
| VM_INS_POP_REG | pop_reg | Pop to virtual register | 1 byte: register index |
| VM_INS_PUSH_IMM | push_imm | Push immediate | 1-8 bytes: value |
| VM_INS_ADD | add | Add (with flags) | 0 bytes (operands on V-stack) |
| VM_INS_NOR | nor | NOT(NOT a AND NOT b) = ~(a\|b) | 0 bytes |
| VM_INS_NAND | nand | NOT(NOT a OR NOT b) = ~(a&b) | 0 bytes |
| VM_INS_STR | store | Store to memory | Variable |
| VM_INS_LDR | load | Load from memory | Variable |
| VM_INS_SHL/SHR/ROL/ROR | shift | Bit shifts/rotates | 1 byte: count |
| VM_INS_SHLD/SHRD | double_shift | Double precision shifts | 1 byte: count |
| VM_INS_MUL/IMUL | multiply | Unsigned/signed multiply | 0 bytes |
| VM_INS_DIV/IDIV | divide | Unsigned/signed divide | 0 bytes |
| VM_INS_CALL | call | Call external function | 1 byte: arg count |
| VM_INS_CRC | crc | Integrity check | 0 bytes (CRC of code) |
| VM_INS_RDTSC | rdtsc | Read timestamp counter | 0 bytes (anti-debug) |
| VM_INS_CPUID | cpuid | CPU identification | 0 bytes (anti-debug) |
| VM_INS_LOCK_XCHG | lock_xchg | Atomic exchange | 0 bytes |
| VM_INS_PUSH_CRX | push_crx | Push control register | 0 bytes |
| VM_INS_POP_CRX | pop_crx | Pop control register | 0 bytes |
| VM_INS_PUSH_SP | push_sp | Push virtual stack pointer | 0 bytes |
| VM_INS_POP_SP | pop_sp | Pop virtual stack pointer | 0 bytes |
| VM_INS_POP_EFLAGS | pop_flag | Pop flags | 0 bytes |
| VM_INS_EXIT | exit | Exit VM, restore context | 0 bytes |

### Stack-Based VM

VMP is a **stack-based virtual machine**:

- Operations pop operands from the virtual stack
- Push results back to virtual stack
- Virtual stack is in the VM context (heap memory)
- Real x86 registers are saved/restored around VM execution

Example: `ADD` instruction
```
Pop T0 from V-stack
Pop T1 from V-stack
T2 = T1 + T0
Set EFLAGS (SF, ZF, CF, OF)
Push T2 to V-stack
Push EFLAGS to V-stack
```

The `NOR` and `NAND` instructions implement universal logic gates — any boolean operation can be built from these.

---

## 4. Handler Dispatch

### Handler Table

In `.vmp1`, there's a table of handler addresses indexed by opcode (after decryption). Each handler is a chunk of x86 code that implements one VM instruction.

The dispatch loop:
```
1. Fetch encrypted byte from [VM_IP] → decrypt with current key
2. Use decrypted opcode as index into handler table
3. JMP to handler code
4. Handler executes, updates VM state, modifies key
5. JMP back to dispatch loop
```

### Handler Recognition (from NoVmpy)

NoVmpy identifies handlers by pattern-matching the x86 code. Each handler has a characteristic x86 instruction sequence:

```python
# Example: ADD handler pattern
mh.load(0, {'size': 'size'})           # load first operand from V-stack
mh.load(align_size(mh.get_ph('size'))) # load second operand
mh.match(X86_INS_ADD, [...])            # x86 ADD instruction
mh.store(bridge.size)                   # store result back
mh.store_eflags()                       # store flags
```

### Self-Modification of Handlers

VMP can also self-modify handlers at runtime (observed in our trace). The first execution of a handler may patch itself for subsequent executions.

---

## 5. VM Context Structure (Reconstructed)

The `VM_CONTEXT` struct on the heap contains:

```c
struct vm_context {
    uint8_t  saved_regs[16 * 8];   // 16 x86 GP registers (64-bit each)
    uint64_t flags;                  // EFLAGS
    uint8_t  vregs[N * 8];          // Virtual register file (N virtual registers)
    uint64_t vip;                    // Virtual instruction pointer (encrypted)
    uint64_t vsp;                    // Virtual stack pointer (into V-stack)
    uint64_t key;                    // Current XOR cipher key
    uint32_t dir;                    // Direction (1 = forward, -1 = backward)
    // ... handler table base, rebase offset, etc.
};
```

From NoVmpy `VMConfig`:
```python
class VMConfig:
    reg_key    # x86 register holding encryption key
    reg_ip     # x86 register holding VIP
    reg_sp     # x86 register holding VSP
    reg_regs   # x86 register pointing to virtual register file base
    reg_base   # x86 register for handler table base
    dir        # bytecode direction (+1 or -1)
    rebase     # image base adjustment
```

---

## 6. Devirtualization Approaches

### The 5-Stage Pipeline (Industry Standard)

Modern devirtualization follows a rigorous pipeline:

```
Phase 1: CFG Exploration & Execution Tracing
Phase 2: Semantic Extraction (Taint + Symbolic Exec)
Phase 3: Lifting to IR (LLVM-IR / VTIL / P-Code / Microcode)
Phase 4: Optimization Passes (DCE, Constant Prop, MBA solving)
Phase 5: Recompilation / Lowering to x86
```

### A. Static Pattern-Matching (Legacy — NoVmp, vmp2, VmpHelper)

**How it works:**
1. Parse PE, find `.vmp0`/`.vmp1` sections
2. Auto-discover VM entries in `.text` (CALL/JMP cross-section patterns)
3. Match handler x86 code patterns → assign semantics
4. Decrypt bytecode, decode VM instruction stream
5. Lift to IL (VTIL), apply optimizations, output x86

**Tools:**
- **NoVmp** (can1357): VTIL-based, VMP 2.x-early 3.x. Static lift + VTIL opt → x86
- **vmp2** (backengineering): Unicorn-based `vmemu` + LLVM `vmdevirt`. Profiles handlers, explores virtual JCCs via emulation
- **VmpHelper** (fjqisba): IDA plugin using Ghidra SLEIGH. VMP 3.5 x86 only
- **VMAttack** (anatolikalysch): IDA plugin. Grading system combines static + dynamic analysis

**Critical warning (from vmp2 author):** "Pattern matching is effectively dead. Modern protectors randomize and morph handlers for every compilation. Your code must analyze WHAT the handler achieves (semantics), not what it looks like."

**Limitations:**
- VMP 3.5+ VEH-based dispatch → no x86 code at CALL target
- Handler morphing defeats pattern matching
- Context pointers are heap addresses → unresolvable statically
- MBA obfuscation hides simple operations behind complex expressions

### B. Dynamic Symbolic Execution (Triton / rr / PIN)

**How it works (from VMProtect-devirtualization by JonathanSalwan):**
1. Trace execution of VMP-protected function (via PIN, rr, or GDB)
2. Record ALL instructions executed (register states + opcodes)
3. Replay trace in Triton with symbolic execution
4. Make function inputs symbolic (e.g., RDI, RSI)
5. Execute all instructions symbolically
6. **Key insight:** VM machinery instructions (dispatch, handler table lookup, key update) don't depend on symbolic inputs → get CONCRETIZED
7. Only original program's logic (XOR, ADD, etc.) survives as symbolic expressions
8. Output: LLVM IR of devirtualized function

**The concretization process:**
```
Before: (bvxor (bvadd (_ bv0 32) x) (bvlshr (concat ...) ...))
                    ↑ VM noise           ↑ user data
After concretization:
         (bvxor x y)    → simple XOR of 2 inputs
```

**TritonDSE** (Quarkslab): High-level framework on top of Triton. Provides:
- Program loading (LIEF/cle)
- Memory segmentation with permissions
- Coverage strategies (block/edge/path)
- Automatic input injection
- Hook mechanism for custom instrumentation
- Currently supports ELF + Linux only

**Requirements:**
- Live execution trace of the VMP function (PIN, rr, GDB)
- Triton for symbolic execution
- LLVM for optimization + recompilation

**Advantages over static:**
- Bypasses all VMP obfuscation (VEH, self-modification, handlers)
- Works with heap-allocated contexts
- No need to decrypt bytecode manually
- Handles all VMP versions uniformly

### C. LLVM-Based Lifting (SATURN)

**SATURN** framework (academic): Lifts binary → LLVM-IR → iterative CFG reconstruction using compiler optimizations + SMT solving. Key principles:
- "Does not make any assumptions about the obfuscated code"
- Uses LLVM's built-in optimizations (DCE, constant propagation, etc.) + Souper Optimizer
- Iterative CFG construction: execute, collect branches, solve with Z3, merge
- Can weaken/remove: constant unfolding, MBA expressions, dead code, bogus CFG, integer encoding
- Output can be recompiled with any LLVM backend

### D. Hybrid (Our Approach)

1. Dump decrypted PE sections from runtime memory (LD_PRELOAD dumper)
2. Reconstruct PE with decrypted sections (`.vmp0` populated)
3. For context-table VMP (Loader.exe): NoVmp can process if stubs unmodified
4. For VEH-based VMP (Memory.dll): Need Triton to emulate VEH + trace from export entry
5. **Limitation:** VEH dispatch requires runtime VEH registration — can't be statically reconstructed

### E. Decompiler-Specific Approaches

Each decompiler handles devirtualization differently:

| Decompiler | IR Layer | Approach |
|-----------|----------|----------|
| **IDA Pro (Hex-Rays)** | Microcode API | Plugins inject custom microcode at `MMAT_GLBOPT`/`MMAT_LVARS` maturity levels. Skips x86 layer entirely |
| **Ghidra** | P-Code / SLEIGH | Can write custom processor module defining VMP bytecode as "assembly" → automatic decompilation. Or inject P-Code snippets |
| **Binary Ninja** | LLIL → MLIL → HLIL | Clean Python/C++ API for custom architectures. Best for writing devirtualization plugins |
| **Radare2 / Rizin** | ESIL | Good for quick tracing/emulation. Harder to reconstruct clean pseudo-C |

---

## 7. The LLVM-Based VMP Devirtualization Pipeline (from hackyboiz blog)

The blog at hackyboiz.github.io describes a clean LLVM-based approach:

```
1. Identify virtualized function + its arguments
2. Generate VMP execution trace
3. Replay trace with Triton, construct symbolic expressions
4. Concretize non-input-dependent branches (strips VM machinery)
5. Lift symbolic expressions to LLVM-IR
6. Apply LLVM optimizations (-O3, DCE, constant propagation)
7. Compile LLVM-IR back to native x86
8. Patch cleaned code back into binary (over .vmp sections)
```

Key insight: **You don't need to understand VMP's bytecode format.** The symbolic execution + concretization approach automatically separates VM machinery from original program logic. LLVM optimizations clean up the result.

## 8. Our Tool Arsenal

| Tool | Status | Capability | Limitation |
|------|--------|-----------|------------|
| **NoVmp** (can1357) | ✅ Built (14MB binary) | Static devirtualization for VMP 2.x-early 3.x | Fails on VMP 3.5+ self-modified entries |
| **Triton** (JonathanSalwan) | ✅ Installed (Python + C++ lib) | Symbolic execution engine, concretization | Needs traces or live execution |
| **VMProtect-devirtualization** | ✅ Cloned | PIN-trace → Triton → LLVM pipeline | PIN URL dead, needs trace adapter |
| **NoVmpy** (wallds) | ✅ Cloned (Python) | VMP handler identification + VTIL lifter | Needs IDA, VTIL-Python C++ ext won't build |
| **rr** | ✅ Installed | Linux process recorder/replay | Already available |
| **Reconstructed PE** | ✅ 16MB file | Decrypted .vmp0 + .vmp1 from runtime dump | Entry stubs self-modified, context pointers stale |
| **VMP3-Disasm** | ❌ API mismatch | Experimental VMP bytecode disassembler | Needs old Triton API |

### Build Status Summary

```
NoVmp:
  ✅ Capstone 5 (system), patched to avoid fetch
  ✅ Keystone LLVM headers patched (#include <cstdint>)
  ✅ VTIL-Core task.hpp patched (#include <utility>)
  ✅ Pause calls removed (Linux compat)
  ✅ Binary: ~/RE/culmaster/tools/novmp/build_clang/NoVmp/NoVmp

Triton:
  ✅ Python bindings from git source (not pip — pip has OpenAI's ML Triton)
  ✅ C++ lib system-installed at /usr/lib/libtriton.so
  ✅ cmake config at /usr/lib/cmake/triton/tritonConfig.cmake

Reconstructed PE:
  ✅ 3 dump files merged covering full PE image
  ✅ All sections patched with runtime-decrypted data
  ✅ File: ~/RE/culmaster/bin/loader_reconstructed.exe
```

---

## 8.1 Concrete Trace Analysis (Our VMP Entry)

```
Entry at .vmp0+0x8E38B (VA 0x1401BE38B):

0x1401BE38B: 90                    NOP
0x1401BE38C: 5B                    POP RBX          ; gets 0x1401BE395 (ret addr)
0x1401BE38D: E9 B9 76 05 00       JMP 0x140215A4B  ; → dispatcher

Dispatcher:
0x140215A4B: 48 87 1C 24          XCHG [RSP], RBX  ; swap with stack
0x140215A4F: 53                   PUSH RBX          ; save old
0x140215A50: 0F BF DC             MOVSX EBX, SP     ; stack → ebx
0x140215A53: 66 41 0F B6 DF       MOVZX BX, R15B    ; low byte R15
0x140215A58: 0F CB                BSWAP EBX         ; endian swap
0x140215A5A: 48 8D 1D 6E E7 DE FF LEA RBX, [RIP-0x211892] → 0x1400041CF
0x140215A61: E9 AB C1 FF FF       JMP 0x140211C11
0x140211C11: 48 8B 9B 41 FE 2F 00 MOV RBX, [RBX+0x2FFE41] ; read context ptr
                    ; reads from .vmp0+0x1D4010 = 0x6FFFE CE5CD1E (Wine heap)
0x140211C18: E9 5C 58 0D 00       JMP 0x1402E7479
0x1402E7479: 48 8D 9B EA 1B BB 12 LEA RBX, [RBX+0x12BB1BEA] ; context base adjust
0x1402E7480: E9 A6 3D FF FF       JMP 0x1402DB22B
0x1402DB22B: 48 87 1C 24          XCHG [RSP], RBX  ; context ptr → stack
0x1402DB22F: E9 14 92 03 00       JMP 0x140314448
0x140314448: C3                   RET               ; → context ptr (garbage)
```

**Key observations:**
- Dispatcher uses JMP chains (obfuscation)
- Multiple XCHG with stack (anti-analysis)
- Context pointer derived from table + base adjustment
- RET doesn't return to caller — jumps to context structure
- All instructions between POP and final RET are context pointer computation

---

## 9. PE Reconstruction Recipe

To reconstruct a decrypted PE from runtime memory dumps:

```python
# 1. Collect /proc/pid/mem dumps for the PE image range
# 2. Merge dumps into contiguous memory buffer
# 3. For each PE section, patch raw data:
#    - Read section content from memory buffer
#    - Update section header raw pointer + size
#    - Append section data to PE file
# 4. File: ~/RE/culmaster/tools/reconstruct_pe.py
#
# Critical: dumps must be captured BEFORE VMP self-modifies entries
# (impossible with LD_PRELOAD — it hooks at process start, but VMP
#  initialization happens before any user code runs)
```

---

## 10. Key Insights for Future VMP Work

### Paradigm Shift

1. **Pattern matching is dead.** Modern VMP randomizes/morphs handlers per compilation. Must analyze **semantics** (what the handler achieves using symbolic execution), not **syntax** (what instructions it contains).

2. **The CFG is the bottleneck, not the math.** SMT solvers (Z3) handle MBA reliably. The hard problem is recovering virtual control flow (Virtual JCCs) — missed branches = broken decompilation.

3. **VMP has two dispatch models:**
   - **Context-table** (Loader.exe): Self-modifying stubs, heap context pointers, resolvable with runtime dumps + NoVmp
   - **VEH-based** (Memory.dll): Page fault dispatch, `.vmp0` as no-access, hybrid native+VM functions, no self-modification

### Practical Approaches

4. **For VEH-based VMP:** Must emulate the VEH handler in Triton. The VEH decodes bytecode key from stack, dispatches to handlers in `.vmp1`. Triton can register a page fault callback that implements the VMP dispatch.

5. **Dynamic tracing is the most reliable path:** rr + GDB scripting (if rr works on CPU) or TritonDSE for ELF. PIN is dead (Intel removed downloads).

6. **For Memory.dll/Check.exe:** We CAN load them in Wine and call exports. We have:
   - Full runtime memory dumps of decrypted sections ✅
   - Export RVAs (ReadByte=+0x1560, etc.) ✅
   - Entry stubs verified (no self-modification) ✅
   - Understanding of VEH dispatch mechanism ✅
   - Triton for symbolic execution ✅

### What's Needed to Complete Devirtualization

7. **To devirtualize Memory.dll exports:**
   - Write Triton page fault handler for `.vmp0` region
   - Register it before executing the export
   - When CALL to `.vmp0` faults, Triton VEH reads:
     - Fault address = which VM function
     - Stack key = entry point within bytecode
   - VEH fetches bytecodes from `.vmp0`, decrypts with rolling XOR
   - VEH dispatches to handlers in `.vmp1`
   - After bytecode execution, VEH modifies RIP to return address
   - Triton extracts symbolic expressions naturally via concretization

8. **Alternative: Use TritonDSE** for guided exploration + path solving. Load the full reconstructed PE, register VEH callback, explore all paths.

### Tool-Specific Notes

9. **NoVmp** works for pre-3.5 VMP with context-table dispatch. Our build (patched for GCC 16) handles Loader.exe style.

10. **vmp2 toolkit** archived but its `vmemu` approach (Unicorn-based CFG exploration) is the right design pattern. Author explicitly warns against handler pattern matching.

11. **SATURN** proves LLVM-based lifting works generically — no VMP-specific logic needed. Lifts to LLVM-IR, optimizes with LLVM passes, recompiles.

12. **Binary Ninja** is the best decompiler for writing devirtualization plugins (clean Python/C++ API, HLIL). IDA Microcode API is more powerful but closed/proprietary.

---

## 11. References

### Devirtualization Tools

| Tool | Author | Stars | Approach | Link |
|------|--------|-------|----------|------|
| NoVmp | can1357 | 2.1k | Static VTIL lift for VMP 3.x x64 | https://github.com/can1357/NoVmp |
| NoVmpy | wallds | 439 | Python VTIL + IDA plugin | https://github.com/wallds/NoVmpy |
| VMProtect-devirtualization | JonathanSalwan | 1.4k | Dynamic: PIN → Triton → LLVM | https://github.com/JonathanSalwan/VMProtect-devirtualization |
| vmp2 | backengineering | 118 | Unicorn + LLVM for VMP2 (archived) | https://github.com/backengineering/vmp2 |
| VMAttack | anatolikalysch | 874 | IDA plugin, grading analysis | https://github.com/anatolikalysch/VMAttack |
| VmpHelper | fjqisba | 388 | IDA plugin + Ghidra SLEIGH | https://github.com/fjqisba/VmpHelper |
| SATURN | Garba/Favaro | — | Academic LLVM deobfuscation | https://arxiv.org/abs/1909.01752 |
| titan | archercreat | 132 | LLVM devirtualizer | https://github.com/archercreat/titan |

### Infrastructure

| Project | Purpose | Link |
|---------|---------|------|
| VTIL-Core | Devirtualization IR framework | https://github.com/vtil-project/VTIL-Core |
| VTIL-Python | Python bindings for VTIL | https://github.com/vtil-project/VTIL-Python |
| VTIL-NativeLifters | x86 → VTIL lifter | https://github.com/vtil-project/VTIL-NativeLifters |
| VTIL-BinaryNinja | BN plugin for VTIL | https://github.com/vtil-project/VTIL-BinaryNinja |
| Triton | Dynamic symbolic execution library | https://github.com/JonathanSalwan/Triton |
| TritonDSE | High-level exploration framework | https://github.com/quarkslab/tritondse |
| Triton docs | Doxygen API reference | https://triton-library.github.io/documentation/doxygen/index.html |

### Educational Resources

| Resource | Author | Content | Link |
|----------|--------|---------|------|
| VMP 3.x blog | r0da | Deep VMP 3.x internals | https://whereisr0da.github.io/blog/posts/2021-02-16-vmp-3/ |
| secret.club series | — | LLVM lifting for VMP (3 parts) | https://secret.club/2021/09/08/vmprotect-llvm-lifting-1.html |
| back.engineering | — | VMP analysis series | https://back.engineering/17/05/2021/ |
| Titan devirtualizer | Mitchell Zakocs | VMP3 analysis | https://www.mitchellzakocs.com/blog/vmprotect3 |
| USENIX WOOT'09 | Rolf Rolles | Pioneering VM unpacking | https://www.usenix.org/legacy/event/woot09/tech/full_papers/rolles.pdf |
| DIMVA 2018 | Salwan/Bardin/Potet | Triton deobfuscation paper | https://github.com/JonathanSalwan/Triton/blob/master/publications/DIMVA2018-slide-deobfuscation-salwan-bardin-potet.pdf |
| Quarkslab TritonDSE | Robin David | TritonDSE introduction | https://blog.quarkslab.com/introducing-tritondse-a-framework-for-dynamic-symbolic-execution-in-python.html |
| VMP devirtualization review | gonchik | JonathanSalwan project review | https://gonchik.medium.com/unveiling-the-vmprotect-devirtualization-project-a-review-that-project-4ecb55796200 |

### Our Local Files

- Reconstructed Loader.exe PE: `~/RE/culmaster/bin/loader_reconstructed.exe`
- Reconstructed Memory.dll PE: `~/RE/culmaster/payloads/Memory_reconstructed.dll`
- NoVmp build: `~/RE/culmaster/tools/novmp/build_clang/NoVmp/NoVmp`
- NoVmpy source: `~/RE/NoVmpy/novmpy/` (handler.py, vm.py, vm_const.py, vm_lifter.py)
- VMProtect-devirtualization scripts: `~/RE/VMProtect-devirtualization/`
- Runtime dumps: `~/RE/culmaster/dumps/`
- Memory.dll runtime sections: `~/.wine/drive_c/mem_{text,vmp0,vmp1}.bin`
- VMP knowledge doc: `~/RE/culmaster/notes/VMP_INTERNALS.md`
- Tooling fixes: `~/RE/culmaster/notes/TOOLING_FIXES.md`

## 12. Current Interpreter Status (2026-05-28)

### What We Have
- VMP bytecode interpreter skeleton: `~/RE/culmaster/notes/vmp_interp.py`
  - 22 opcodes defined (from NoVmpy)
  - Rolling XOR fetch mechanism
  - Stack-based VM state (16 vregs, vstack, flags)
  - 10+ opcode implementations (NOP, PUSH_REG, POP_REG, PUSH_IMM, ADD, NOR, NAND, SHL, SHR, ROL, ROR, MUL, DIV, EXIT, PUSH_SP, POP_SP, POP_FLAGS)
  - Still needs: LOAD, STORE, CALL, CRC, RDTSC, CPUID, LOCK_XCHG, PUSH/POP_CRX, SHLD/SHRD, signed ops

### What We Know (but haven't solved)
- Bytecodes live in `.vmp0` region
- They're encrypted with a decoder-specific scheme (not just rolling XOR with fixed key)
- NoVmpy's `decode_emu()` function shows the decryption is implemented as x86 instruction emulation
- The decoder varies per binary — VMP generates it at compile time
- `.vmp0+0xC9FE2` and `.vmp0+0x6DCFF` are the entry points for ReadByte's two VMP calls
- DECRYPTED `.vmp0` data still has ENCRYPTED bytecodes — VMP decrypts on fetch, not at load time
- EXIT opcode (0x21) found at `.vmp0+0xC9F09` and `.vmp0+0x6DCEC` (near our entry points) but surrounding bytes aren't valid opcodes with key=0

### Next Steps
1. Find the decoder x86 instructions in the dispatcher code
2. Implement `decode_emu()` equivalent in Python using those instructions
3. Decrypt the bytecodes
4. Feed plain opcodes through the interpreter
5. Connect interpreter to Triton VEH handler
6. Execute and extract symbolic expressions

### Key Insight
The VMP bytecode encryption is a SELF-MODIFYING stream cipher where the key register
is modified by each decrypted byte AND by the decoder x86 instructions (ADD, XOR, ROL, etc.
applied to the key register). The decoder pattern is detected by NoVmpy's `MatchHelper`.

## 13. Final Architecture (Memory.dll — 2026-05-28)

### Dispatch Chain (Confirmed)
```
ReadByte (normal x86 function):
  push rbx, push rbp, push rsi, sub rsp, 0x50
  mov ebp, edx     ; save arg2
  mov ebx, ecx     ; save arg1
  mov ecx, 0x18    ; VM key
  push rcx
  call .vmp0+0xC9FE2  → entry stub:
                           NOP
                           MOVSX ECX, R15B
                           POP RCX (return addr)
                           JMP dispatcher chain
                              → LEA + MOV (context table lookup)
                              → LEA + XCHG + RET
                              → heap trampoline (JMP [RIP+off])
                              → dispatcher in .vmp1
                              → fetch+decrypt bytecodes from .vmp0
                              → dispatch handlers
  test rax, rax    ; check return
  ...
  ret
```

### Key Findings
1. **Two CALLs per export** — ReadByte has 2 VMP calls (at +0x26 and +0x33)
2. **Heap trampolines** — context table at .vmp0+0x1EC219 contains heap pointers to executable trampoline code (WOW64 gate stubs)
3. **Trampoline static** — before/after execution identical
4. **Bytecodes encrypted** — in .vmp0, decrypted on-the-fly by x86 decoder
5. **No VEH** — dispatch works via RET to heap trampoline, NOT page faults
6. **Context table + adjustment** — table value + 0x3D894CFE = heap trampoline address

### What We Built
- VMP interpreter skeleton with 18/22 opcodes
- Triton VEH handler (intercepts CALL to .vmp0)
- Reconstructed PE (Memory.dll with decrypted sections)
- Context table dumper/analyzer
- rr trace with wine-staging (fully operational)
- 657 lines of VMP_INTERNALS.md documentation

### What Remains
1. Find the ACTUAL bytecode decoder x86 code in .vmp0/.vmp1
2. Implement decoder emulation in Python (from NoVmpy decode_emu)
3. Decrypt bytecodes → feed through interpreter
4. Connect interpreter to Triton for symbolic execution

### Tools We've Gained
```
Built/Working:
✅ NoVmp — static devirt for context-table VMP
✅ Triton — symbolic execution engine
✅ VMP interpreter skeleton — 18/22 opcodes
✅ PE reconstructor — merge runtime dumps into usable PE
✅ Memory.dll section dumper — capture from live Wine
✅ Context table extractor — find VM structures in .vmp0
✅ rr + wine-staging — full execution tracing (zen-fixed)
✅ TON of VMP knowledge — one of the most documented public resources
```

## 14. Decoder Search Status

The bytecode decoder is a sequence of x86 instructions that manipulate a key register
before XOR'ing with the encrypted byte. Found candidates in .vmp1 around:
- 0x4ae2fb: `xor r9b, r10b` `ror r9b, 1` `add r9b, 0x4b` `rol r9b, 1`
- 0x4ae461: `xor ebx, r8d` `inc ebx` `not ebx`
- 0x4ae5e9: `neg r8b` `xor r8b, 0x10` `dec r8b`
- 0x4ae6d2: `add r8b, 0x5a` `ror r8b, 1` `xor r11b, r8b`
- 0x4ae8a2: `xor ecx, r11d` `bswap ecx` `not ecx`

These are different DECODERS for different handler contexts. VMP generates unique
decoder sequences per handler group. Next step: extract the decoder that maps to
ReadByte's entry point and implement Python equivalent.

### Full Session Summary (2026-05-28)

**What we accomplished:**
1. Full Loader.exe RE (4127 functions via Ghidra)
2. All 6 payloads downloaded from live C&C (78.142.210.147)
3. VMP 3.5+ architecture: context-table + VEH-based dispatch
4. NoVmp built natively (patched for GCC 16 + system capstone)
5. Triton installed and tested
6. Reconstructed PEs with decrypted runtime sections
7. wine-staging + rr working (Zen boot param fix)
8. Memory.dll runtime sections dumped (.text, .vmp0, .vmp1, heap context)
9. VMP bytecode interpreter skeleton (18/22 opcodes)
10. Triton VEH handler (intercepts CALL to .vmp0)
11. Context table located (.vmp0+0x1EC219)
12. Heap trampoline code captured
13. VMP_INTERNALS.md: 718 lines
14. TOOLING_FIXES.md: build recipes
15. Full toolchain: ghidra, NoVmp, Triton, rr, GDB, capstone, unicorn

**Remaining for complete devirtualization:**
- Extract bytecode decoder from .vmp1 candidates
- Implement decode_emu() in Python
- Connect interpreter to Triton VEH
- Execute ReadByte through full pipeline
- Extract symbolic expression of original logic

## 15. FINAL ARCHITECTURE VERIFIED (2026-05-29 00:20)

### VMP 3.5+ Dispatch (Memory.dll)
```
ReadByte stub (x86):
  mov ecx, 0x18    ; VM key/entry ID
  push rcx
  call .vmp0+0x59FE2  ← This address contains VM BYTECODE, not x86!
                          ↓
                    PAGE FAULT (VEH intercepts)
                          ↓
                    VEH reads fault address → bytecode ID
                    reads encrypted bytecodes from .vmp0
                    decrypts with custom decoder (NOT simple XOR)
                    dispatches handlers
                    modifies CONTEXT.RIP to return address
                          ↓
                    Back to ReadByte epilogue
```

### Critical Difference from VMP 2.x-3.0
- **Old VMP:** CALL target has x86 `PUSH key; CALL dispatcher` → NoVmp works
- **VMP 3.5+:** CALL target has VM BYTECODE → page fault → VEH interprets → NoVmp CANNOT work

### What We Have
- Encrypted bytecodes at `.vmp0+0x59FE2` (initial key 0x18)
- Encrypted bytecodes for 2nd call at `.vmp0+0x6DCFF` (initial key 0x00)
- Heap executable regions dumped (580KB + 208KB)
- VEH handler code somewhere in heap regions
- All sections dumped and reconstructed

### What Remains
1. Find VEH handler code in heap regions (search for `RtlAddVectoredExceptionHandler` or exception handling patterns)
2. Reverse VEH's bytecode decryption algorithm
3. Implement in Python interpreter
4. Connect to Triton → devirtualize

### NoVmp Compatibility
NoVmp CANNOT handle VMP 3.5+ with VEH-based dispatch. It expects x86 entry stubs.
Use Triton VEH handler approach instead.

## 16. CORRECT ARCHITECTURE (2026-05-29 01:00) — BREAKTHROUGH!

### What We Got WRONG (most of the session)
- ❌ VEH-based dispatch: .vmp0 is PAGE_NOACCESS → causes page fault
- ❌ Bytecode location: .vmp0+0x59FE2
- ❌ Initial key 0x18 used directly for decryption
- ❌ Decoder sequence in .vmp1

### What is CORRECT
- ✅ .vmp0 is EXECUTE_READ (PAGE_EXECUTE_READ = 0x20) — NOT no-access!
- ✅ No VEH involved! Normal CALL + execution through x86 entry stub
- ✅ CALL target: .vmp0+0xC9FE2 (NOT +0x59FE2!)
- ✅ Entry stub IS valid x86: `NOP; MOVSX ECX, R15B; POP RCX; JMP dispatcher`
- ✅ Dispatchers at .vmp0+0x8321B (follows JMP from entry)
- ✅ Context table at .vmp0+0x1EC219 (confirmed)
- ✅ Heap trampoline at table_value + 0x3D894CFE (confirmed)
- ✅ Dispatchers chain: entry → .vmp0 dispatcher → context table → heap → dispatch loop
- ✅ NoVmp crashes on VMP 3.5+ dispatcher format (incompatible prologue)

### Verified at Runtime
```
ReadByte at runtime:
  push rbx, push rbp, push rsi, sub rsp, 0x50
  ...security cookie setup...
  mov ecx, 0x18          ; VM key/entry ID
  push rcx
  call .vmp0+0xC9FE2     ; → entry stub (EXECUTABLE x86 code!)
                              ↓
                         NOP
                         MOVSX ECX, R15B
                         POP RCX
                         JMP .vmp0+0x8321B
                              ↓
                         XCHG [RSP], RCX
                         PUSH RCX
                         MOVSXD RCX, EBX
                         LEA RCX, [RIP - 0x89CE6]
                         MOV RCX, [RCX + 0x1F2CD5]  ← context table
                         LEA RCX, [RCX + 0x3D894CFE]
                         XCHG [RSP], RCX
                         RET → heap trampoline
                              ↓
                         JMP [RIP + GOT_offset]
                              ↓
                         heap dispatch loop
```

### What We STILL Need
- The bytecode decryption (happens inside the heap dispatch loop)
- Context structure layout (key, VIP, VSP on heap)
- Mapping from entry ID (0x18) to bytecodes

### Key Confirmation
`.vmp0` is normal executable memory. No VEH. No page faults.
VMP 3.5+ uses a HEAP-BASED dispatch where VM state lives on heap.
