//! Byte-level handler templates for the synthetic-sample builder.
//!
//! Split from `synthetic_sample.rs` via `#[path]` include so the impl
//! file stays under the project's 500-line ceiling (same convention
//! as `junk_stripper.rs` / `junk_stripper_length.rs`).
//!
//! # Structural dispatcher chain
//!
//! Emitted into `.text` and picked up by
//! [`crate::protector_signals::scan_rx_sections_for_dispatcher`]. The
//! four required byte-level primitives are:
//! - `MOV r, [r]` — indirect load (`0x8B`, mod=00, r/m not 4/5).
//! - `XOR r, imm32` — group-1 imm with reg-field 6, mod=11 (modrm in
//!   `0xF0..=0xF7`).
//! - `ADD r, r/m` — opcode `0x03`, any ModR/M.
//! - `JMP [r]` — `FF /4` indirect jump (modrm reg-field 4).
//!
//! # Handler shells
//!
//! Each template targets a specific [`crate::handler_semantic::VmpSemantic`]
//! matcher. Bodies are aligned to `HANDLER_SLOT_SIZE` bytes with `0x90`
//! (NOP) padding so the 100-byte read the classifier performs never
//! straddles two handlers. The tail `add VIP, 4; jmp [VSP]` is shared
//! across every reachable handler and is what generates the bulk of
//! the register-role vote's VIP signal.
//!
//! # Register conventions
//!
//! - x64: VSP=R14, VIP=R15, VKEY=R11. Bytecode uses REX.WB (`0x49`) as
//!   the standard prefix for r14/r15/r11 access.
//! - x86: VSP=ESI, VIP=EDI, VKEY=EBX. No REX prefix.
//!
//! The counters the voter in [`crate::register_roles`] accumulates are
//! carefully balanced across the 30-handler mix so:
//! - VSP wins by dominance (>60% of indirect load/store touches).
//! - VIP wins because it has zero indirect-store touches (filtered)
//!   plus a monotonic `add VIP, imm8` bump in nearly every handler.
//! - VKEY wins because 5 handlers carry an `xor VKEY, imm32` step.

// ---------------------------------------------------------------------
// Structural dispatcher
// ---------------------------------------------------------------------

/// Return the byte sequence for the structural VMP dispatcher chain
/// used inside `.text`. Encodes `mov r14,[r15]; xor r14,imm32;
/// add r14,r15; jmp [r14]` on x64, or the analogous
/// `mov esi,[edi]; xor esi,imm32; add esi,ebx; jmp [esi]` on x86.
pub(super) fn structural_dispatcher_bytes(is_64: bool) -> Vec<u8> {
    if is_64 {
        // 4D 8B 37       ; mov r14, [r15]      (REX.WB, opcode 8B, ModRM 37 = mod=00 rm=7 → r15)
        // 49 81 F6 ..    ; xor r14, imm32      (REX.WB, opcode 81, ModRM F6 = /6 rm=6 → r14)
        // 4D 03 F7       ; add r14, r15        (REX.WB, opcode 03, ModRM F7 = mod=11 reg=6 rm=7)
        // 41 FF 26       ; jmp [r14]           (REX.B,  opcode FF, ModRM 26 = /4 rm=6 → r14)
        vec![
            0x4D, 0x8B, 0x37, 0x49, 0x81, 0xF6, 0xEF, 0xBE, 0xAD, 0xDE, 0x4D, 0x03, 0xF7, 0x41, 0xFF, 0x26,
        ]
    } else {
        // 8B 37          ; mov esi, [edi]
        // 81 F6 ..       ; xor esi, imm32
        // 03 F3          ; add esi, ebx
        // FF 26          ; jmp [esi]
        vec![0x8B, 0x37, 0x81, 0xF6, 0xEF, 0xBE, 0xAD, 0xDE, 0x03, 0xF3, 0xFF, 0x26]
    }
}

// ---------------------------------------------------------------------
// Handler slot assembly
// ---------------------------------------------------------------------

/// Build the concatenated handler-body region: 30 handlers, each
/// padded with `0x90` to `slot_size` bytes. Returned as one contiguous
/// buffer so the caller can memcpy it into a section body.
pub(super) fn build_handler_slots(is_64: bool, slot_size: usize) -> Vec<u8> {
    let bodies = if is_64 { handlers_x64() } else { handlers_x86() };
    let mut out = Vec::with_capacity(bodies.len() * slot_size);
    for body in &bodies {
        assert!(
            body.len() <= slot_size,
            "handler body ({} bytes) does not fit into a {}-byte slot",
            body.len(),
            slot_size
        );
        out.extend_from_slice(body);
        // Pad with `0x90` (NOP) so the classifier's 100-byte read window
        // never crosses into an adjacent handler. `resize` is idiomatic
        // for a fixed-value fill and satisfies clippy::same_item_push.
        out.resize(out.len() + (slot_size - body.len()), 0x90);
    }
    out
}

// ---------------------------------------------------------------------
// x86-64 handler templates (VSP=r14, VIP=r15, VKEY=r11)
// ---------------------------------------------------------------------

/// Common tail: `add r15, 4; jmp [r14]`.
const X64_TAIL: [u8; 7] = [0x49, 0x83, 0xC7, 0x04, 0x41, 0xFF, 0x26];

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

fn handlers_x64() -> Vec<Vec<u8>> {
    let mut out = Vec::new();

    // 3x Rdtsc: `rdtsc; mov [r14], rax; <tail>`
    let rdtsc = concat(&[&[0x0F, 0x31, 0x49, 0x89, 0x06], &X64_TAIL]);
    for _ in 0..3 {
        out.push(rdtsc.clone());
    }
    // 3x Cpuid: `cpuid; mov [r14], rax; <tail>`
    let cpuid = concat(&[&[0x0F, 0xA2, 0x49, 0x89, 0x06], &X64_TAIL]);
    for _ in 0..3 {
        out.push(cpuid.clone());
    }
    // 1x Vmexit: `popfq; ret`
    out.push(vec![0x9D, 0xC3]);

    // 3x Nand: 2 NOT + AND reg-reg + load/store [r14] + tail.
    let nand = concat(&[
        &[0x49, 0x8B, 0x06],       // mov rax, [r14]
        &[0x49, 0x8B, 0x4E, 0x08], // mov rcx, [r14+8]
        &[0xF7, 0xD0],             // not eax
        &[0xF7, 0xD1],             // not ecx
        &[0x21, 0xC8],             // and eax, ecx
        &[0x49, 0x89, 0x06],       // mov [r14], rax
        &X64_TAIL,
    ]);
    for _ in 0..3 {
        out.push(nand.clone());
    }
    // 3x Nor: same shape with OR instead of AND.
    let nor = concat(&[
        &[0x49, 0x8B, 0x06],
        &[0x49, 0x8B, 0x4E, 0x08],
        &[0xF7, 0xD0],
        &[0xF7, 0xD1],
        &[0x09, 0xC8], // or eax, ecx
        &[0x49, 0x89, 0x06],
        &X64_TAIL,
    ]);
    for _ in 0..3 {
        out.push(nor.clone());
    }
    // 4x PushImm: `mov rax,[r15]; sub r14,8; mov [r14],rax; <tail>`.
    let push_imm = concat(&[
        &[0x49, 0x8B, 0x07],       // mov rax, [r15] (VIP fetch)
        &[0x49, 0x83, 0xEE, 0x08], // sub r14, 8
        &[0x49, 0x89, 0x06],       // mov [r14], rax
        &X64_TAIL,
    ]);
    for _ in 0..4 {
        out.push(push_imm.clone());
    }
    // 3x Add: `mov rax,[r14]; mov rcx,[r14+8]; add rax,rcx; pushfq; mov [r14],rax; <tail>`.
    let add = concat(&[
        &[0x49, 0x8B, 0x06],
        &[0x49, 0x8B, 0x4E, 0x08],
        &[0x49, 0x01, 0xC8], // add rax, rcx (reg-reg)
        &[0x9C],             // pushfq
        &[0x49, 0x89, 0x06],
        &X64_TAIL,
    ]);
    for _ in 0..3 {
        out.push(add.clone());
    }
    // 3x Popreg: `mov rax,[r14]; add r14,8; mov [rbp+8],rax; <tail>`.
    let popreg = concat(&[
        &[0x49, 0x8B, 0x06],
        &[0x49, 0x83, 0xC6, 0x08], // add r14, 8
        &[0x48, 0x89, 0x45, 0x08], // mov [rbp+8], rax
        &X64_TAIL,
    ]);
    for _ in 0..3 {
        out.push(popreg.clone());
    }
    // 2x Ldd: 2 indirect loads + indirect store + add r14,imm8 + tail.
    let ldd = concat(&[
        &[0x49, 0x8B, 0x06],
        &[0x49, 0x8B, 0x0E], // mov rcx, [r14]
        &[0x49, 0x89, 0x06],
        &[0x49, 0x83, 0xC6, 0x08],
        &X64_TAIL,
    ]);
    for _ in 0..2 {
        out.push(ldd.clone());
    }
    // 5x Vjmp with VKEY signal: `xor r11, imm32; mov rax, [r14]; <tail>`.
    let vjmp_key = concat(&[
        &[0x49, 0x81, 0xF3, 0xEF, 0xBE, 0xAD, 0xDE], // xor r11, 0xDEADBEEF
        &[0x49, 0x8B, 0x06],
        &X64_TAIL,
    ]);
    for _ in 0..5 {
        out.push(vjmp_key.clone());
    }
    // 1x Popf: bare `popfq; jmp [r14]` (no C3 in the trailing 32 bytes
    // so `is_vmexit` doesn't win over `is_popf_shape`).
    out.push(vec![0x9D, 0x41, 0xFF, 0x26]);

    out
}

// ---------------------------------------------------------------------
// x86 handler templates (VSP=esi, VIP=edi, VKEY=ebx)
// ---------------------------------------------------------------------

/// Common tail: `add edi, 4; jmp [esi]`.
const X86_TAIL: [u8; 5] = [0x83, 0xC7, 0x04, 0xFF, 0x26];

fn handlers_x86() -> Vec<Vec<u8>> {
    let mut out = Vec::new();

    // 3x Rdtsc
    let rdtsc = concat(&[&[0x0F, 0x31, 0x89, 0x06], &X86_TAIL]);
    for _ in 0..3 {
        out.push(rdtsc.clone());
    }
    // 3x Cpuid
    let cpuid = concat(&[&[0x0F, 0xA2, 0x89, 0x06], &X86_TAIL]);
    for _ in 0..3 {
        out.push(cpuid.clone());
    }
    // 1x Vmexit
    out.push(vec![0x9D, 0xC3]);

    // 3x Nand
    let nand = concat(&[
        &[0x8B, 0x06],
        &[0x8B, 0x4E, 0x08],
        &[0xF7, 0xD0],
        &[0xF7, 0xD1],
        &[0x21, 0xC8],
        &[0x89, 0x06],
        &X86_TAIL,
    ]);
    for _ in 0..3 {
        out.push(nand.clone());
    }
    // 3x Nor
    let nor = concat(&[
        &[0x8B, 0x06],
        &[0x8B, 0x4E, 0x08],
        &[0xF7, 0xD0],
        &[0xF7, 0xD1],
        &[0x09, 0xC8],
        &[0x89, 0x06],
        &X86_TAIL,
    ]);
    for _ in 0..3 {
        out.push(nor.clone());
    }
    // 4x PushImm
    let push_imm = concat(&[
        &[0x8B, 0x07],       // mov eax, [edi] (VIP fetch)
        &[0x83, 0xEE, 0x08], // sub esi, 8
        &[0x89, 0x06],
        &X86_TAIL,
    ]);
    for _ in 0..4 {
        out.push(push_imm.clone());
    }
    // 3x Add
    let add = concat(&[
        &[0x8B, 0x06],
        &[0x8B, 0x4E, 0x08],
        &[0x01, 0xC8],
        &[0x9C],
        &[0x89, 0x06],
        &X86_TAIL,
    ]);
    for _ in 0..3 {
        out.push(add.clone());
    }
    // 3x Popreg
    let popreg = concat(&[&[0x8B, 0x06], &[0x83, 0xC6, 0x08], &[0x89, 0x45, 0x08], &X86_TAIL]);
    for _ in 0..3 {
        out.push(popreg.clone());
    }
    // 2x Ldd
    let ldd = concat(&[
        &[0x8B, 0x06],
        &[0x8B, 0x0E],
        &[0x89, 0x06],
        &[0x83, 0xC6, 0x08],
        &X86_TAIL,
    ]);
    for _ in 0..2 {
        out.push(ldd.clone());
    }
    // 5x Vjmp with VKEY signal
    let vjmp_key = concat(&[
        &[0x81, 0xF3, 0xEF, 0xBE, 0xAD, 0xDE], // xor ebx, 0xDEADBEEF
        &[0x8B, 0x06],
        &X86_TAIL,
    ]);
    for _ in 0..5 {
        out.push(vjmp_key.clone());
    }
    // 1x Popf
    out.push(vec![0x9D, 0xFF, 0x26]);

    out
}
