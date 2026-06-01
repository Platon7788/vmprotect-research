#!/usr/bin/env python3
"""
Unicorn Dispatch Table Extractor
Extracts dispatch table via CPU emulation using Python unicorn library.
"""

import sys
import json
import struct
import logging
from pathlib import Path

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
    from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX
except ImportError:
    print("Error: unicorn library not found. Install with: pip install unicorn", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

class DispatchExtractor:
    def __init__(self, binary_path, dispatch_table_va, entry_point_va, image_base):
        self.binary_path = binary_path
        self.dispatch_table_va = dispatch_table_va
        self.entry_point_va = entry_point_va
        self.image_base = image_base
        self.entries = []
        self.entry_count = 0
        
    def load_pe_sections(self, uc, binary_data):
        """Load PE sections into Unicorn memory."""
        # Parse PE header
        if binary_data[:2] != b'MZ':
            raise ValueError("Not a valid PE binary")
        
        pe_offset = struct.unpack('<I', binary_data[0x3c:0x40])[0]
        
        # Get number of sections
        num_sections = struct.unpack('<H', binary_data[pe_offset + 0x06:pe_offset + 0x08])[0]
        
        # Get size of optional header
        opt_header_size = struct.unpack('<H', binary_data[pe_offset + 0x14:pe_offset + 0x16])[0]
        
        # Section header starts after optional header
        section_offset = pe_offset + 0x18 + opt_header_size
        
        PAGE_SIZE = 0x1000
        
        log.info(f"Loading {num_sections} sections from offset 0x{section_offset:x}")
        
        for i in range(num_sections):
            sec_hdr = binary_data[section_offset + i * 40:section_offset + (i + 1) * 40]
            
            sec_name = sec_hdr[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
            virtual_size = struct.unpack('<I', sec_hdr[8:12])[0]
            virtual_addr = struct.unpack('<I', sec_hdr[12:16])[0]
            raw_size = struct.unpack('<I', sec_hdr[16:20])[0]
            raw_ptr = struct.unpack('<I', sec_hdr[20:24])[0]
            
            if virtual_size == 0:
                continue
            
            section_va = self.image_base + virtual_addr
            
            # Align to page size
            aligned_va = section_va & ~(PAGE_SIZE - 1)
            aligned_size = ((virtual_size + (section_va - aligned_va) + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE
            
            section_data = binary_data[raw_ptr:raw_ptr + raw_size]
            
            # Pad to aligned size
            if len(section_data) < aligned_size:
                section_data += b'\x00' * (aligned_size - len(section_data))
            
            try:
                uc.mem_map(aligned_va, aligned_size)
                uc.mem_write(aligned_va, section_data[:aligned_size])
                log.info(f"Loaded section {sec_name:8} at 0x{section_va:x} (aligned: 0x{aligned_va:x}, size: 0x{aligned_size:x})")
            except Exception as e:
                log.error(f"Failed to load section {sec_name}: {e}")
    
    def mem_write_hook(self, uc, addr, size, value):
        """Hook for memory writes to dispatch table."""
        if addr >= self.dispatch_table_va and addr < self.dispatch_table_va + 256 * 8:
            offset = addr - self.dispatch_table_va
            opcode = offset // 8
            
            encrypted = value & ((1 << (size * 8)) - 1)
            
            # Try to extract XOR key from registers
            xor_key = self.extract_xor_key(uc, encrypted)
            decrypted = encrypted ^ xor_key
            
            log.debug(f"Dispatch entry {opcode}: encrypted=0x{encrypted:x}, key=0x{xor_key:x}, decrypted=0x{decrypted:x}")
            
            self.entries.append({
                'opcode': opcode,
                'write_va': addr,
                'encrypted': encrypted,
                'xor_key': xor_key,
                'decrypted': decrypted,
            })
            
            self.entry_count += 1
            if self.entry_count >= 256:
                log.info("Captured all 256 dispatch entries")
    
    def extract_xor_key(self, uc, encrypted):
        """Extract XOR key from CPU context."""
        try:
            rax = uc.reg_read(UC_X86_REG_RAX)
            if self.is_valid_xor_key(rax, encrypted):
                return rax
        except:
            pass
        
        try:
            rcx = uc.reg_read(UC_X86_REG_RCX)
            if self.is_valid_xor_key(rcx, encrypted):
                return rcx
        except:
            pass
        
        try:
            rdx = uc.reg_read(UC_X86_REG_RDX)
            if self.is_valid_xor_key(rdx, encrypted):
                return rdx
        except:
            pass
        
        return 0
    
    def is_valid_xor_key(self, key, encrypted):
        """Check if key produces valid address."""
        decrypted = encrypted ^ key
        return decrypted >= self.image_base and decrypted < self.image_base + 0x80000000
    
    def extract(self):
        """Run emulation and extract dispatch table."""
        log.info(f"Starting Unicorn emulation")
        log.info(f"  Dispatch table VA: 0x{self.dispatch_table_va:x}")
        log.info(f"  Entry point VA: 0x{self.entry_point_va:x}")
        log.info(f"  Image base: 0x{self.image_base:x}")
        
        # Read binary
        with open(self.binary_path, 'rb') as f:
            binary_data = f.read()
        
        # Create Unicorn instance
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        
        # Load sections
        self.load_pe_sections(uc, binary_data)
        
        # Set up stack
        stack_base = self.image_base + 0x200000
        stack_size = 0x100000
        try:
            uc.mem_map(stack_base, stack_size)
            uc.reg_write(UC_X86_REG_RSP, stack_base + stack_size - 8)
            log.info(f"Stack mapped at 0x{stack_base:x}")
        except Exception as e:
            log.warning(f"Failed to set up stack: {e}")
        
        # Add write hook
        uc.hook_add(4, self.mem_write_hook)  # UC_HOOK_MEM_WRITE = 4
        
        # Execute with timeout
        try:
            log.info(f"Starting emulation from 0x{self.entry_point_va:x}")
            uc.emu_start(self.entry_point_va, self.entry_point_va + 0x1000000, timeout=10000000)
        except Exception as e:
            log.info(f"Emulation stopped: {e}")
        
        log.info(f"Captured {len(self.entries)} dispatch entries")
        
        # Sort by opcode
        self.entries.sort(key=lambda e: e['opcode'])
        
        return self.entries

def main():
    if len(sys.argv) < 5:
        print("Usage: unicorn_extractor.py <binary> <dispatch_table_va> <entry_point_va> <image_base> [output_json]")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    dispatch_table_va = int(sys.argv[2], 0)
    entry_point_va = int(sys.argv[3], 0)
    image_base = int(sys.argv[4], 0)
    output_json = sys.argv[5] if len(sys.argv) > 5 else "dispatch_entries.json"
    
    extractor = DispatchExtractor(binary_path, dispatch_table_va, entry_point_va, image_base)
    entries = extractor.extract()
    
    # Write output
    with open(output_json, 'w') as f:
        json.dump(entries, f, indent=2)
    
    log.info(f"Entries exported to: {output_json}")
    
    # Print summary
    valid_count = sum(1 for e in entries if e['decrypted'] >= image_base and e['decrypted'] < image_base + 0x80000000)
    print(f"Valid entries: {valid_count}/{len(entries)}")

if __name__ == '__main__':
    main()
