#!/usr/bin/env python3
"""
Reconstruct Memory.dll PE from runtime section dumps.

Overlays dumped sections onto original PE at correct raw offsets.
Requires pefile.

Usage:
    python3 reconstruct_memory.py --original original.dll --dumps dir/ --output out.dll
"""

import os
import sys
try:
    import pefile
except ImportError:
    print("[-] pip install pefile"); sys.exit(1)


def find_dumps(dump_dir):
    """Return dict: section_va -> (name, data)."""
    dumps = {}
    for fn in sorted(os.listdir(dump_dir)):
        fp = os.path.join(dump_dir, fn)
        if not os.path.isfile(fp) or not fn.startswith('dump_.') or not fn.endswith('.bin'):
            continue
        # dump_.<name>_<VA>.bin
        body = fn[6:-4]
        parts = body.split('_')
        if len(parts) < 2:
            continue
        sec_name = '.' + '_'.join(parts[:-1])
        try:
            va = int(parts[-1], 16)
        except ValueError:
            continue
        with open(fp, 'rb') as f:
            data = f.read()
        dumps[va] = (sec_name, data)
    return dumps


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--original', '-o', required=True)
    ap.add_argument('--dumps', '-d', required=True)
    ap.add_argument('--output', '-O', required=True)
    args = ap.parse_args()

    dumps = find_dumps(args.dumps)
    if not dumps:
        print(f"[-] No dumps in {args.dumps}"); return 1

    print(f"[*] Dumps: {len(dumps)}")
    for va, (nm, d) in sorted(dumps.items()):
        print(f"      {nm:10s} VA={va:#x} ({len(d):,}b)")

    pe = pefile.PE(args.original)

    # Known section layout (raw offset, raw size, name, VA, virtual size)
    known_sects = [
        (0x1000,   0x2118,  '.text',  0x1000,   0x2118),
        (0x4000,   0x179a,  '.rdata', 0x4000,   0x179a),
        (0x6000,   0x720,   '.data',  0x6000,   0x720),
        (0x7000,   0x468,   '.pdata', 0x7000,   0x468),
        (0x8000,   0x35558f,'.vmp0',  0x8000,   0x35558f),
        (0x35e000, 0x52d938,'.vmp1',  0x35e000, 0x52d938),
        (0x88c000, 0x200,   '.reloc', 0x88c000, 0x200),
        (0x88d000, 0x200,   '.rsrc',  0x88d000, 0x200),
    ]

    # Detect base: find vmp0 dump -> known VA 0x8000
    base = next((va - 0x8000 for va, (nm, _) in dumps.items() if 'vmp0' in nm), None)
    if base is None:
        base = next((va - 0x1000 for va, (nm, _) in dumps.items() if 'text' in nm), None)
    if base is None:
        print("[-] Could not detect base offset"); return 1
    print(f"[*] Detected base: {base:#x}")

    # Map dump name -> data for matching
    dump_by_name = {nm: data for va, (nm, data) in dumps.items()}

    replaced = 0
    for ro, rs, sec_name, sec_va, sec_vs in known_sects:
        data = dump_by_name.get(sec_name)
        if data is not None:
            nw = min(len(data), rs) if rs else len(data)
            pe.set_bytes_at_offset(ro, data[:nw])
            print(f"[+] {sec_name:10s} raw@{ro:#x} ({nw:,}/{len(data):,}b)")
            replaced += 1
        else:
            print(f"[.] {sec_name:10s} -> no dump")

    # Fix section table
    CHARACTERISTICS = {
        'CODE': 0x20, 'EXECUTE': 0x20000000, 'READ': 0x40000000,
        'WRITE': 0x80000000, 'DISCARD': 0x2000000, 'DATA': 0x40,
    }
    sec_chars = {
        '.text':  CHARACTERISTICS['CODE'] | CHARACTERISTICS['EXECUTE'] | CHARACTERISTICS['READ'],
        '.rdata': CHARACTERISTICS['DATA'] | CHARACTERISTICS['READ'],
        '.data':  CHARACTERISTICS['DATA'] | CHARACTERISTICS['READ'] | CHARACTERISTICS['WRITE'],
        '.pdata': CHARACTERISTICS['DATA'] | CHARACTERISTICS['READ'],
        '.vmp0':  CHARACTERISTICS['CODE'] | CHARACTERISTICS['EXECUTE'] | CHARACTERISTICS['READ'],
        '.vmp1':  CHARACTERISTICS['DATA'] | CHARACTERISTICS['READ'],
        '.reloc': CHARACTERISTICS['DATA'] | CHARACTERISTICS['READ'] | CHARACTERISTICS['DISCARD'],
        '.rsrc':  CHARACTERISTICS['DATA'] | CHARACTERISTICS['READ'],
    }
    for i, (ro, rs, name, va, vs) in enumerate(known_sects):
        if i < len(pe.sections):
            sec = pe.sections[i]
            sec.Name = name.encode().ljust(8, b'\x00')
            sec.Misc_VirtualSize = vs
            sec.VirtualAddress = va
            sec.SizeOfRawData = rs
            sec.Characteristics = sec_chars.get(name, 0)

    pe.OPTIONAL_HEADER.SizeOfImage = ((known_sects[-1][3] + known_sects[-1][4]) + 0xFFF) & ~0xFFF

    pe.write(args.output)
    size = os.path.getsize(args.output)
    print(f"\n[+] {args.output} ({size:,}b, {replaced} sections)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
