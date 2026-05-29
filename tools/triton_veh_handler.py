#!/usr/bin/env python3
"""
Triton VEH handler: lift VMP dispatch to Triton IR for symbolic analysis.

Combines Win32 VEH (Vectored Exception Handler) with Triton's dynamic
tainting to trace VMP bytecode execution through the heap dispatch loop.

Architecture:
  1. Inject VEH that catches INT3 at the trampoline dispatch table
  2. On each dispatch, record operand states + jump targets
  3. Periodically replay captured traces through Triton to lift bytecode
  4. Search lifted traces for heap decryption key material

Usage (attach to running process):
    python3 triton_veh_handler.py --pid <PID>
    python3 triton_veh_handler.py --dump captured_trace.bin

Requires:
    pip install pywin32 triton
"""

import struct
import sys
import os

try:
    import ctypes
    from ctypes import wintypes
except ImportError:
    ctypes = None

try:
    from triton import (
        TritonContext, ARCH, CPUSIZE, Instruction, OPCODE, MODE,
        MemoryAccess, RegisterOperand, ImmediateOperand, MemoryOperand,
    )
except ImportError:
    TritonContext = None


# --- Configuration ---
VMP_TRAMPOLINE = 0x1800336EF0  # tramp+0x36EF0 (dispatch jump table)
VMP_DISPATCH_TABLE = 0x1800336EF0  # same
VMP_HANDLER_BASE = 0x1800332E78  # tramp base after relocation fixup
STACK_PROBE_DEPTH = 64  # how many dispatch events to capture
CAPTURE_SIZE = 0x10000  # bytes of bytecode per trace


def ensure_capstone():
    try:
        import capstone as _cs
        return _cs
    except ImportError:
        return None


class VMPDispatchRecord:
    """One VMP dispatch event captured via VEH."""
    __slots__ = ('opcode', 'r8_val', 'rdx_val', 'target', 'stack_frame')

    def __init__(self, opcode, r8, rdx, target, stack=None):
        self.opcode = opcode
        self.r8_val = r8
        self.rdx_val = rdx
        self.target = target
        self.stack_frame = stack or {}


class VMPTraceSession:
    """
    Captures VMP dispatch events by injecting INT3 at the jump table
    and recording CPU state in the VEH handler.
    """
    def __init__(self, process_handle=None):
        self.records = []
        self.process_handle = process_handle
        self.bytecode_blob = b''
        self._ctx = None

    def capture_dispatch(self, context):
        """Called from VEH handler — record one dispatch event."""
        # Read opcode from RCX (lea r8, [rcx+2] means opcode at [rcx])
        opcode = self._read_word(context.rcx)
        r8_val = context.r8
        rdx_val = context.rdx
        target = self._resolve_target(opcode)

        rec = VMPDispatchRecord(opcode, r8_val, rdx_val, target)
        self.records.append(rec)

        # Collect bytecode blob from the heap area
        if len(self.bytecode_blob) < CAPTURE_SIZE:
            blob = self._read_mem(rdx_val, 0x200)
            self.bytecode_blob += blob

        if len(self.records) >= STACK_PROBE_DEPTH:
            return False  # stop capturing
        return True

    def _read_word(self, addr):
        if self.process_handle:
            buf = ctypes.create_string_buffer(2)
            nread = ctypes.c_size_t()
            ctypes.windll.kernel32.ReadProcessMemory(
                self.process_handle, addr, buf, 2, ctypes.byref(nread))
            return struct.unpack('<H', buf.raw)[0]
        return 0

    def _read_mem(self, addr, size):
        if self.process_handle:
            buf = ctypes.create_string_buffer(size)
            nread = ctypes.c_size_t()
            ctypes.windll.kernel32.ReadProcessMemory(
                self.process_handle, addr, buf, size, ctypes.byref(nread))
            return buf.raw[:nread.value]
        return b''

    def _resolve_target(self, opcode):
        """Decode jump table entry for given opcode."""
        idx = opcode - 0x45
        if idx < 0 or idx >= 47:
            return 0
        entry_off = idx * 4
        if self.process_handle:
            buf = ctypes.create_string_buffer(4)
            nread = ctypes.c_size_t()
            table_addr = VMP_DISPATCH_TABLE + entry_off
            ctypes.windll.kernel32.ReadProcessMemory(
                self.process_handle, table_addr, buf, 4, ctypes.byref(nread))
            disp = struct.unpack('<i', buf.raw)[0]
            return VMP_DISPATCH_TABLE + disp
        return 0

    def get_unique_opcodes(self):
        return sorted(set(r.opcode for r in self.records))

    def get_stats(self):
        counts = {}
        for r in self.records:
            counts[r.opcode] = counts.get(r.opcode, 0) + 1
        return counts

    def save(self, path):
        """Save captured trace to disk."""
        import json
        # Convert records to JSON-safe dicts
        data = {
            'bytecode_blob': self.bytecode_blob.hex(),
            'records': [
                {'opcode': r.opcode, 'r8': hex(r.r8_val),
                 'rdx': hex(r.rdx_val), 'target': hex(r.target)}
                for r in self.records
            ],
            'stats': self.get_stats(),
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[+] Trace saved: {path} ({len(self.records)} events)")

    def load(self, path):
        """Load previously saved trace."""
        import json
        with open(path) as f:
            data = json.load(f)
        self.bytecode_blob = bytes.fromhex(data['bytecode_blob'])
        self.records = [
            VMPDispatchRecord(r['opcode'], int(r['r8'], 16),
                              int(r['rdx'], 16), int(r['target'], 16))
            for r in data['records']
        ]
        print(f"[*] Loaded trace: {path} ({len(self.records)} events)")
        return self


class TritonLifter:
    """
    Lift VMP dispatch bytecode to Triton IR for symbolic analysis.
    Searches for heap decryption key patterns in the lifted traces.
    """
    KEY_PATTERNS = [
        # Common VMP decryption key sizes
        (4, 'xor'),      # 32-bit XOR key
        (8, 'xor'),      # 64-bit XOR key
        (4, 'add'),      # 32-bit ADD key
        (8, 'add'),      # 64-bit ADD key
        (4, 'rol'),      # 32-bit ROL key
        (8, 'ror'),      # 64-bit ROR key
    ]

    def __init__(self):
        if TritonContext is None:
            raise RuntimeError("Triton not installed (pip install triton)")
        self.ctx = TritonContext(ARCH.X86_64)
        self.ctx.setMode(MODE.CONCRETE, True)
        self.ctx.setConcreteRegisterValue(
            self.ctx.registers.rdx, 0x180000000)
        self.ctx.setConcreteRegisterValue(
            self.ctx.registers.r8,  0x180000002)

    def lift(self, trace: VMPTraceSession):
        """Lift captured bytecode to Triton IR."""
        blob = trace.bytecode_blob
        if not blob:
            print("[-] No bytecode to lift")
            return []

        cs = ensure_capstone()
        if cs is None:
            print("[-] capstone not available, skipping disasm")
            return []

        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        md.detail = True

        lifted = []
        # Disassemble the bytecode blob
        for insn in md.disasm(blob, 0x180000000):
            try:
                # Build Triton instruction
                triton_inst = Instruction()
                triton_inst.setOpcodes(insn.bytes)
                triton_inst.setAddress(insn.address)

                # Process through Triton
                self.ctx.processing(triton_inst)

                lifted.append({
                    'addr': hex(insn.address),
                    'mnemonic': insn.mnemonic,
                    'op_str': insn.op_str,
                    'tainted': triton_inst.isTainted(),
                    'symbolic': triton_inst.isSymbolized(),
                    'type': insn.group_name,
                })
            except Exception as e:
                lifted.append({
                    'addr': hex(insn.address),
                    'error': str(e),
                })

            if len(lifted) >= 1000:
                break

        print(f"[*] Lifted {len(lifted)} instructions via Triton")
        return lifted

    def find_keys(self, lifted):
        """Search lifted trace for potential heap decryption keys."""
        keys = []
        for i, insn in enumerate(lifted):
            if 'error' in insn:
                continue
            mnemonic = insn['mnemonic']
            for size, op in self.KEY_PATTERNS:
                if mnemonic == op or (op == 'xor' and 'xor' in mnemonic):
                    # Check for constant operand
                    op_str = insn['op_str']
                    for part in op_str.split(','):
                        part = part.strip()
                        if part.startswith('0x') or part.startswith('0X'):
                            try:
                                val = int(part, 16)
                                if val != 0:
                                    keys.append({
                                        'addr': insn['addr'],
                                        'value': hex(val),
                                        'size': size,
                                        'type': op,
                                        'mnemonic': mnemonic,
                                        'context': f"{mnemonic} {op_str}",
                                    })
                            except ValueError:
                                pass
        return keys

    def dump_ir(self, lifted, path='vmp_ir_dump.txt'):
        """Dump lifted IR to file."""
        with open(path, 'w') as f:
            f.write(f"# VMP Triton IR Dump\n# {len(lifted)} instructions\n\n")
            for insn in lifted:
                if 'error' in insn:
                    f.write(f"; ERROR @ {insn['addr']}: {insn['error']}\n")
                else:
                    taint_mark = ' [T]' if insn.get('tainted') else ''
                    symb_mark = ' [S]' if insn.get('symbolic') else ''
                    f.write(f"{insn['addr']}: {insn['mnemonic']:10s} "
                            f"{insn['op_str']}{taint_mark}{symb_mark}\n")
        print(f"[+] IR dump: {path}")


# --- VEH Injection (Windows only) ---
if ctypes is not None:
    # Win32 constants
    EXCEPTION_CONTINUE_EXECUTION = -1
    EXCEPTION_CONTINUE_SEARCH = 0
    EXCEPTION_DEBUG_EVENT = 1
    DBG_CONTINUE = 0x00010002
    EXCEPTION_INT3 = 0x80000003

    # VEH callback type
    PVECTORED_EXCEPTION_HANDLER = ctypes.CFUNCTYPE(
        wintypes.LONG, ctypes.c_void_p)


class VmpVeHandler:
    """
    Injects VEH into target process to intercept VMP dispatch.
    Sets INT3 at the jump table and captures state on each trip.
    """
    def __init__(self, pid):
        self.pid = pid
        self._handle = None
        self._handler = None
        self._original_bytes = None
        self._trace = VMPTraceSession()

    def __enter__(self):
        self._open_process()
        self._install_handler()
        self._patch_jump_table()
        return self._trace

    def __exit__(self, *exc):
        self._restore_jump_table()
        # Close handle
        if self._handle:
            ctypes.windll.kernel32.CloseHandle(self._handle)

    def _open_process(self):
        PROCESS_ALL_ACCESS = 0x1F0FFF
        self._handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_ALL_ACCESS, False, self.pid)
        if not self._handle:
            raise RuntimeError(f"OpenProcess({self.pid}) failed: "
                               f"{ctypes.GetLastError()}")

    def _install_handler(self):
        """Add VEH to this process for INT3 at jump table."""
        @PVECTORED_EXCEPTION_HANDLER
        def handler(exception_info):
            rec = ctypes.cast(
                exception_info, ctypes.POINTER(ctypes.c_ubyte * 0x60))
            # Check for INT3 at our jump table address
            context = ctypes.cast(
                exception_info, ctypes.POINTER(
                    ctypes.c_ubyte * 0x4F0))  # CONTEXT size for x64

            # Re-read exception info properly
            class EXCEPTION_POINTERS(ctypes.Structure):
                _fields_ = [
                    ("ExceptionRecord", ctypes.c_void_p),
                    ("ContextRecord", ctypes.c_void_p),
                ]

            ep = EXCEPTION_POINTERS.from_address(exception_info)
            if not ep.ExceptionRecord:
                return EXCEPTION_CONTINUE_SEARCH

            class EXCEPTION_RECORD(ctypes.Structure):
                _fields_ = [
                    ("ExceptionCode", wintypes.DWORD),
                    ("ExceptionFlags", wintypes.DWORD),
                    ("ExceptionRecord", ctypes.c_void_p),
                    ("ExceptionAddress", ctypes.c_void_p),
                    ("NumberParameters", wintypes.DWORD),
                    ("ExceptionInformation", wintypes.DWORD * 15),
                ]

            er = EXCEPTION_RECORD.from_address(ep.ExceptionRecord)
            if er.ExceptionCode != 0x80000003:  # EXCEPTION_BREAKPOINT
                return EXCEPTION_CONTINUE_SEARCH

            # Check if it's at our dispatch table
            if er.ExceptionAddress != ctypes.c_void_p(VMP_TRAMPOLINE):
                return EXCEPTION_CONTINUE_SEARCH

            cr = ctypes.cast(ep.ContextRecord,
                             ctypes.POINTER(ctypes.c_ubyte * 0x4F0))

            # Parse CONTEXT for x64 (simplified)
            # Rcx at offset 0x80, Rdx at 0x88, R8 at 0x90
            regs = (ctypes.c_uint64 * 0x4F0).from_address(ep.ContextRecord)
            # These offsets are for CONTEXT on x64 Windows
            # Rcx = 0x80/8 = 16, Rdx = 0x88/8 = 17, R8 = 0x90/8 = 18
            _RIP_OFF = 0x98 // 8  # 19
            _RCX_OFF = 0x80 // 8
            _RDX_OFF = 0x88 // 8
            _R8_OFF = 0x90 // 8

            # Read regs via array
            reg_arr = ctypes.cast(ep.ContextRecord,
                                  ctypes.POINTER(ctypes.c_uint64 * 64))
            rcx_val = reg_arr.contents[_RCX_OFF]
            rdx_val = reg_arr.contents[_RDX_OFF]
            r8_val = reg_arr.contents[_R8_OFF]

            # Read opcode from [rcx]
            opcode_buf = ctypes.c_uint16()
            nread = ctypes.c_size_t()
            ctypes.windll.kernel32.ReadProcessMemory(
                self._handle,
                ctypes.c_void_p(rcx_val),
                ctypes.byref(opcode_buf),
                2, ctypes.byref(nread))

            continue_capture = self._trace.capture_dispatch(
                type('ctx', (), {'rcx': rcx_val, 'rdx': rdx_val,
                                 'r8': r8_val})())

            if not continue_capture:
                # Restore original bytes and remove INT3
                self._restore_jump_table()
                return EXCEPTION_CONTINUE_SEARCH

            # Advance RIP past INT3
            reg_arr.contents[_RIP_OFF] += 1  # INT3 is 1 byte
            return EXCEPTION_CONTINUE_EXECUTION

        self._handler = handler
        veh = ctypes.windll.kernel32.AddVectoredExceptionHandler(1, handler)
        if not veh:
            raise RuntimeError("AddVectoredExceptionHandler failed")
        print(f"[+] VEH installed at {veh:#x}")

    def _patch_jump_table(self):
        """Patch first entry of jump table with INT3 (0xCC)."""
        INT3 = b'\xcc'
        buf = ctypes.create_string_buffer(1)
        nread = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(
            self._handle,
            ctypes.c_void_p(VMP_TRAMPOLINE),
            buf, 1, ctypes.byref(nread))
        self._original_bytes = buf.raw

        nwritten = ctypes.c_size_t()
        ctypes.windll.kernel32.WriteProcessMemory(
            self._handle,
            ctypes.c_void_p(VMP_TRAMPOLINE),
            INT3, 1, ctypes.byref(nwritten))
        print(f"[+] INT3 patch at {VMP_TRAMPOLINE:#x}")

    def _restore_jump_table(self):
        if self._original_bytes and self._handle:
            nwritten = ctypes.c_size_t()
            ctypes.windll.kernel32.WriteProcessMemory(
                self._handle,
                ctypes.c_void_p(VMP_TRAMPOLINE),
                self._original_bytes, 1, ctypes.byref(nwritten))
            self._original_bytes = None
            print("[*] Jump table restored")


# --- Standalone Analysis ---
def analyze_trace_file(path):
    """Load a saved trace and run Triton analysis."""
    if TritonContext is None:
        print("[-] pip install triton"); return

    session = VMPTraceSession().load(path)
    print(f"[*] Loaded trace with {len(session.records)} events")
    print(f"[*] Unique opcodes seen: {session.get_unique_opcodes()}")
    print(f"[*] Bytecode blob: {len(session.bytecode_blob)} bytes")
    print(f"[*] Dispatch stats: {session.get_stats()}")

    lifter = TritonLifter()
    lifted = lifter.lift(session)
    keys = lifter.find_keys(lifted)

    print(f"\n=== Potential Heap Keys ({len(keys)} found) ===")
    for k in keys[:20]:
        print(f"  {k['addr']}: {k['context']} <- constant {k['value']}")

    if keys:
        print("\n[!] Key candidates detected! Verify against vmp1 section.")
    else:
        print("\n[-] No obvious keys found. Try deeper symbolic analysis.")

    lifter.dump_ir(lifted, 'vmp_ir_dump.txt')
    return lifted, keys


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description='Triton VEH handler for VMP bytecode tracing')
    ap.add_argument('--pid', type=int, help='Target process PID')
    ap.add_argument('--dump', help='Analyze saved trace file')
    ap.add_argument('--save', help='Save trace to path')
    ap.add_argument('--dry-run', action='store_true',
                    help='Analyze captured records without injection')
    args = ap.parse_args()

    if args.dump:
        analyze_trace_file(args.dump)
        return

    if args.pid:
        if ctypes is None:
            print("[-] Windows required for VEH injection"); return 1
        print(f"[*] Attaching to PID {args.pid}")
        with VmpVeHandler(args.pid) as trace:
            import time
            print("[*] Capturing dispatches for 10 seconds...")
            time.sleep(10)

        print(f"[*] Captured {len(trace.records)} dispatch events")
        if args.save:
            trace.save(args.save)

        if trace.records:
            if TritonContext is not None:
                lifter = TritonLifter()
                lifted = lifter.lift(trace)
                keys = lifter.find_keys(lifted)
                print(f"\n=== Keys found: {len(keys)} ===")
                for k in keys[:10]:
                    print(f"  {k['addr']}: {k['context']}")
                lifter.dump_ir(lifted, 'vmp_ir_dump.txt')
        return

    # Dry-run mode: demonstrate with synthetic data
    if args.dry_run:
        print("[*] Dry run: synthetic trace analysis")
        if TritonContext is None:
            print("[*] Triton not available, running capstone-only lift")
        session = VMPTraceSession()
        # Simulate some dispatch events
        for opcode in range(0x45, 0x4C):
            session.records.append(VMPDispatchRecord(
                opcode, 0x180000000, 0x180000000 + opcode * 0x100, 0))
        session.bytecode_blob = (
            b'\x48\x31\xd2'  # xor rdx, rdx
            b'\x48\xb8\xef\xbe\xad\xde\x00\x00\x00\x00'  # movabs rax, 0xdeadbeef
            b'\x48\x31\xd0'  # xor rax, rdx
            b'\xc3'  # ret
        ) * 4

        if TritonContext is not None:
            lifter = TritonLifter()
            lifted = lifter.lift(session)
            keys = lifter.find_keys(lifted)
            print(f"[*] Lifted: {len(lifted)} instructions")
            print(f"[*] Keys found: {len(keys)}")
        else:
            # Capstone-only analysis
            cs = ensure_capstone()
            if cs:
                md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
                count = sum(1 for _ in md.disasm(session.bytecode_blob, 0))
                print(f"[*] Disassembled: {count} instructions (capstone)")
            else:
                print("[!] Neither Triton nor capstone available")
        return

    ap.print_help()


if __name__ == '__main__':
    sys.exit(main() if 'main' in dir() else 1)
