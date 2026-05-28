"""
VMP 3.5+ Bytecode Interpreter — skeleton with opcode definitions
"""
import struct

# Opcodes (from NoVmpy)
OPCODES = {
    1: "NOP", 2: "PUSH_REG", 3: "POP_REG", 4: "PUSH_IMM",
    5: "CALL", 6: "CRC", 7: "ADD", 8: "NOR",
    9: "STORE", 10: "LOAD", 11: "NAND",
    12: "RCL", 13: "RCR", 14: "ROL", 15: "ROR",
    16: "SAL", 17: "SAR", 18: "SHL", 19: "SHR",
    20: "SHLD", 21: "SHRD", 22: "MUL", 23: "IMUL",
    24: "DIV", 25: "IDIV", 26: "RDTSC", 27: "CPUID",
    28: "LOCK_XCHG", 29: "PUSH_CRX", 30: "POP_CRX",
    31: "PUSH_SP", 32: "POP_SP", 33: "EXIT", 34: "POP_FLAG",
}

class VMPInterp:
    def __init__(self, bc, key=0):
        self.bc = bc
        self.key = key
        self.vip = 0
        self.vsp = 0
        self.vregs = [0]*16
        self.vstack = []
        self.flags = 0
        self.halted = False
        self.count = 0

    def fetch(self):
        if self.vip >= len(self.bc):
            raise IndexError("BC EOF")
        b = (self.bc[self.vip] ^ self.key) & 0xFF
        self.key = (self.key ^ b) & 0xFF
        self.vip += 1
        return b

    def step(self):
        op = self.fetch()
        name = OPCODES.get(op, f"???")
        self.count += 1
        # Stub — just log
        print(f"  [{self.count:>4}] 0x{self.vip-1:04x}: {name} (0x{op:02x})")
        if op == 33:
            self.halted = True
        return op

    def run(self):
        while not self.halted and self.vip < len(self.bc):
            self.step()
        print(f"  --- {self.count} instructions ---")

# Minimal test
bc_demo = bytes([4, 0x42, 0, 0, 0, 33])  # push_imm 0x42; exit (unencrypted)
vm = VMPInterp(bc_demo, key=0)
vm.run()
