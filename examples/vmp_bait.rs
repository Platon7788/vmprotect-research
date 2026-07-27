//! VMProtect bait — a small Windows PE with distinctive algorithmic
//! hot-loops for VMProtect to virtualise, so `vmp_devirt` has real
//! samples to run against.
//!
//! Build:
//!   cargo build --release --example vmp_bait --target x86_64-pc-windows-msvc
//!   # or --target x86_64-pc-windows-gnu on Linux
//!
//! Full workflow (source → protected .exe → `cargo test --features
//! real-samples`) documented in `docs/VMP_BAIT.md`.
//!
//! WHY these functions:
//!
//! Each `#[no_mangle] pub extern "C"` function below is a symbol
//! VMProtect can discover from the PE export table and mark for
//! virtualisation from its GUI. The five functions cover the
//! semantic-classifier families this crate detects:
//!
//! - [`bait_fibonacci`]     -> `Add` matcher (ADD-heavy loop).
//! - [`bait_crc32`]         -> `Nand`/`Nor` matchers (De Morgan-ish XOR
//!   /SHR/AND chains VMProtect folds into NOR-chains).
//! - [`bait_bubble_sort`]   -> `Vjmp`/`Ret` matchers (compare-and-swap
//!   nested loops = many conditional branches).
//! - [`bait_reverse_bytes`] -> `Ldd`/`Str` matchers (per-byte load and
//!   store to computed offsets).
//! - [`bait_xor_chain`]     -> per-version `CryptoScheme` exercise
//!   (multiplicative XOR chain shaped like VMP's own rolling key).
//!
//! `main` prints each result to stdout so a human tester can verify
//! the protected binary still runs correctly after VMProtect wraps
//! the marked functions. Any behavioural mismatch means VMP itself
//! mis-virtualised the code, not that `vmp_devirt` mis-analysed it —
//! useful signal to keep separate from tool bugs.

// -- Payloads ---------------------------------------------------------

/// Iterative Fibonacci — arithmetic-dominant loop.
///
/// Shape a devirt should see after VMProtect handles this:
/// - Many `Add` semantic matches from the accumulator update.
/// - Some `Popreg`/`PushImm` from the loop counter + local swap.
/// - Trailing `Ret`.
#[unsafe(no_mangle)]
pub extern "C" fn bait_fibonacci(n: u64) -> u64 {
    if n < 2 {
        return n;
    }
    let mut a: u64 = 0;
    let mut b: u64 = 1;
    let mut i: u64 = 2;
    while i <= n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
        i = i.wrapping_add(1);
    }
    b
}

/// Bitwise CRC32 (poly 0xEDB88320, IEEE) — XOR/SHR/AND-dominant.
///
/// Shape a devirt should see:
/// - `Nand`/`Nor` from the De Morgan-shaped mask computations
///   (`crc & 1` and `& mask` sequences).
/// - `Shl`/`Shr` from the `>> 1` per-bit shift.
/// - Very long handler chain from the nested per-bit loop.
///
/// # Safety
/// `data` must point to at least `len` valid, initialised bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bait_crc32(data: *const u8, len: usize) -> u32 {
    // SAFETY: caller must pass a valid slice of `len` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(data, len) };
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in bytes {
        crc ^= u32::from(byte);
        let mut bit = 0u32;
        while bit < 8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            bit = bit.wrapping_add(1);
        }
    }
    !crc
}

/// Bubble sort in place on a fixed-size u32 array — control-flow-heavy.
///
/// Shape a devirt should see:
/// - Many `Vjmp` matches from the compare-and-branch bodies.
/// - `Popreg`/`PushImm` from the temporary swap variable.
/// - Handlers for the outer + inner counter increment.
///
/// # Safety
/// `data` must point to at least `len` valid, mutable, initialised u32s.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bait_bubble_sort(data: *mut u32, len: usize) {
    if len < 2 {
        return;
    }
    // SAFETY: caller must pass a valid mutable slice of `len` u32s.
    let arr = unsafe { core::slice::from_raw_parts_mut(data, len) };
    let mut swapped = true;
    let mut passes: usize = 0;
    while swapped && passes < len {
        swapped = false;
        let mut i: usize = 1;
        while i < len - passes {
            if arr[i - 1] > arr[i] {
                arr.swap(i - 1, i);
                swapped = true;
            }
            i = i.wrapping_add(1);
        }
        passes = passes.wrapping_add(1);
    }
}

/// Reverse a byte slice in place — pure load/store to computed offsets.
///
/// Shape a devirt should see:
/// - `Ldd` and `Str` matches from the two indexed reads and swap
///   writes.
/// - A single symmetric outer loop.
///
/// # Safety
/// `data` must point to at least `len` valid, mutable, initialised bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bait_reverse_bytes(data: *mut u8, len: usize) {
    if len < 2 {
        return;
    }
    // SAFETY: caller must pass a valid mutable slice of `len` bytes.
    let arr = unsafe { core::slice::from_raw_parts_mut(data, len) };
    let mut lo: usize = 0;
    let mut hi: usize = len - 1;
    while lo < hi {
        arr.swap(lo, hi);
        lo = lo.wrapping_add(1);
        hi = hi.wrapping_sub(1);
    }
}

/// Multiplicative XOR chain — shaped like VMProtect's own per-handler
/// rolling-key mixing. Feeds an obvious signal into the
/// `CryptoScheme` per-version dispatcher.
///
/// Shape a devirt should see:
/// - Many `xor r, imm`/`xor r, r` sequences (the `has_xor_reg_imm`
///   primitive we broadened in Commit T).
/// - `Mul`/`Imul` from the `wrapping_mul(31)` step.
/// - `Popf` at the arithmetic boundaries.
#[unsafe(no_mangle)]
pub extern "C" fn bait_xor_chain(seed_a: u64, seed_b: u64, rounds: u64) -> u64 {
    let mut key = seed_a;
    let mut val = seed_b;
    let mut i: u64 = 0;
    while i < rounds {
        key = key.wrapping_mul(31).wrapping_add(val);
        val ^= key;
        val = val.rotate_left(5);
        val = val.wrapping_add(i);
        key ^= val;
        i = i.wrapping_add(1);
    }
    key ^ val
}

// -- Driver -----------------------------------------------------------

fn main() {
    let n: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(20);

    // Fibonacci
    let fib = bait_fibonacci(n);
    println!("fib({n}) = {fib}");

    // CRC32 — SAFETY: msg is a live slice of msg.len() bytes.
    let msg = b"Hello, VMProtect!";
    let crc = unsafe { bait_crc32(msg.as_ptr(), msg.len()) };
    println!("crc32(\"Hello, VMProtect!\") = 0x{crc:08X}");

    // Bubble sort — deterministic input so protected + unprotected
    // outputs match byte-for-byte, letting a human verify the
    // VMProtect wrap didn't corrupt anything.
    // SAFETY: arr is a live mutable slice of arr.len() u32s.
    let mut arr: [u32; 10] = [5, 3, 8, 1, 9, 2, 7, 4, 6, 0];
    unsafe { bait_bubble_sort(arr.as_mut_ptr(), arr.len()) };
    println!("sorted = {arr:?}");

    // Reverse bytes — SAFETY: buf is a live mutable Vec.
    let mut buf: Vec<u8> = b"VMProtect".to_vec();
    unsafe { bait_reverse_bytes(buf.as_mut_ptr(), buf.len()) };
    println!("reversed = {}", String::from_utf8_lossy(&buf));

    // XOR chain
    let x = bait_xor_chain(0xDEAD, 0xBEEF, n);
    println!("xor_chain({n} rounds) = 0x{x:016X}");
}
