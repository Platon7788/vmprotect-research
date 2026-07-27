use super::*;

// ---------------------------------------------------------------------
// Placeholder scheme — regression coverage for the pre-Commit-M callers
// ---------------------------------------------------------------------

#[test]
fn test_decrypt_operand() {
    let mut cryptor = OpcodeCryptor::new();
    cryptor.set_crc(0xDEAD_BEEFu64);
    let encrypted = 0x42u8;
    let decrypted = cryptor.decrypt_operand(encrypted, 1);

    // XOR with low byte of CRC (0xEF): 0x42 ^ 0xEF = 0xAD
    assert_eq!(decrypted, 0x42 ^ 0xEF);
}

#[test]
fn test_crc_update_matches_documented_formula() {
    // Pin down the exact `crc * 31 + val` recurrence — the earlier
    // `assert_ne!(after, before)` accepted any monotonic-ish update
    // (e.g. `crc + val`, `crc ^ val`) as valid, letting a formula
    // regression silently corrupt every downstream operand decode.
    let mut cryptor = OpcodeCryptor::new();
    cryptor.set_crc(0);

    cryptor.update_crc(0x11);
    assert_eq!(cryptor.get_crc(), 0u64.wrapping_mul(31).wrapping_add(0x11));

    cryptor.update_crc(0x22);
    assert_eq!(cryptor.get_crc(), 0x11u64.wrapping_mul(31).wrapping_add(0x22));

    cryptor.update_crc(0x33);
    let expected_after_third = 0x11u64
        .wrapping_mul(31)
        .wrapping_add(0x22)
        .wrapping_mul(31)
        .wrapping_add(0x33);
    assert_eq!(cryptor.get_crc(), expected_after_third);
}

/// A u32 round-trip: encrypt bytes locally (mirroring the decrypt +
/// update_crc cycle), then decrypt via the public API and assert both
/// the returned value and the resulting cryptor state.
#[test]
fn decrypt_value_u32_round_trip() {
    let plaintext: u32 = 0xDEAD_BEEF;
    let plain_bytes = plaintext.to_le_bytes();
    let mut mirror_crc: u64 = 0x1234_5678;
    let mut encrypted = [0u8; 4];
    for (i, &b) in plain_bytes.iter().enumerate() {
        encrypted[i] = b ^ (mirror_crc as u8);
        mirror_crc = mirror_crc.wrapping_mul(31).wrapping_add(b as u64);
    }

    let mut cryptor = OpcodeCryptor::new();
    cryptor.set_crc(0x1234_5678);
    let decoded = cryptor.decrypt_value_u32(&encrypted);

    assert_eq!(decoded, plaintext);
    assert_eq!(cryptor.get_crc(), mirror_crc);
}

/// Same idea for u64 — guards `decrypt_value_u64`'s from_le_bytes
/// assembly against endianness / index mistakes.
#[test]
fn decrypt_value_u64_round_trip() {
    let plaintext: u64 = 0xCAFE_BABE_DEAD_BEEF;
    let plain_bytes = plaintext.to_le_bytes();
    let mut mirror_crc: u64 = 0xA5A5_A5A5;
    let mut encrypted = [0u8; 8];
    for (i, &b) in plain_bytes.iter().enumerate() {
        encrypted[i] = b ^ (mirror_crc as u8);
        mirror_crc = mirror_crc.wrapping_mul(31).wrapping_add(b as u64);
    }

    let mut cryptor = OpcodeCryptor::new();
    cryptor.set_crc(0xA5A5_A5A5);
    let decoded = cryptor.decrypt_value_u64(&encrypted);

    assert_eq!(decoded, plaintext);
    assert_eq!(cryptor.get_crc(), mirror_crc);
}

// ---------------------------------------------------------------------
// CryptoScheme::for_version routing table
// ---------------------------------------------------------------------

#[test]
fn for_version_maps_each_bucket_to_expected_scheme() {
    assert_eq!(CryptoScheme::for_version(VmpVersion::Vmp1), CryptoScheme::None);
    assert_eq!(CryptoScheme::for_version(VmpVersion::Vmp2), CryptoScheme::Vmp2Rolling);
    assert_eq!(
        CryptoScheme::for_version(VmpVersion::Vmp30),
        CryptoScheme::Vmp3PerHandler
    );
    assert_eq!(
        CryptoScheme::for_version(VmpVersion::Vmp35),
        CryptoScheme::Vmp3PerHandler
    );
    assert_eq!(
        CryptoScheme::for_version(VmpVersion::Vmp36Plus),
        CryptoScheme::Vmp3PerHandler
    );
    assert_eq!(
        CryptoScheme::for_version(VmpVersion::Unknown),
        CryptoScheme::Placeholder
    );
}

#[test]
fn new_with_scheme_records_the_scheme() {
    let c = OpcodeCryptor::new_with_scheme(CryptoScheme::Vmp2Rolling);
    assert_eq!(c.scheme(), CryptoScheme::Vmp2Rolling);
}

// ---------------------------------------------------------------------
// Scheme::None — pass-through, no state
// ---------------------------------------------------------------------

#[test]
fn scheme_none_is_identity() {
    let mut c = OpcodeCryptor::new_with_scheme(CryptoScheme::None);
    c.init_from_section(0x1234_5678);
    assert_eq!(c.decrypt_operand(0xAB, 1), 0xAB);
    c.update_crc(0xAB);
    assert_eq!(c.get_crc(), 0, "None scheme carries no state");
    // Repeat: still identity, still zero state.
    assert_eq!(c.decrypt_operand(0xCD, 1), 0xCD);
}

// ---------------------------------------------------------------------
// Vmp2Rolling — encrypt-then-decrypt invertibility + state advancement
// ---------------------------------------------------------------------

/// Inverse of `decrypt_operand` for Vmp2Rolling. Kept in the test
/// module rather than the public API because callers only ever
/// decrypt — the encrypt path exists solely to build test vectors.
fn vmp2_encrypt_byte(plain: u8, key: u64) -> u8 {
    // Decrypt chain: XOR-key -> NEG -> ROL 5 -> INC (wrapping_add 1).
    // Inverse in reverse order: DEC -> ROR 5 -> NEG -> XOR-key.
    let p = plain.wrapping_sub(1);
    let p = p.rotate_right(5);
    let p = p.wrapping_neg();
    p ^ ((key & 0xFF) as u8)
}

#[test]
fn vmp2_encrypt_then_decrypt_is_identity_for_single_byte() {
    // Any real cipher must be invertible; regressions in the op chain
    // that break invertibility break every downstream operand decode.
    for &plain in &[0x00u8, 0x01, 0x42, 0x7F, 0x80, 0xAB, 0xFE, 0xFF] {
        for &key in &[0u64, 1, 0xFF, 0x1234_5678, 0xDEAD_BEEF_CAFE_BABE] {
            let enc = vmp2_encrypt_byte(plain, key);
            let mut c = OpcodeCryptor::new_with_scheme(CryptoScheme::Vmp2Rolling);
            c.set_crc(key);
            let dec = c.decrypt_operand(enc, 1);
            assert_eq!(
                dec, plain,
                "Vmp2 round-trip broke: plain=0x{plain:02x} key=0x{key:x} enc=0x{enc:02x} dec=0x{dec:02x}"
            );
        }
    }
}

#[test]
fn vmp2_decrypt_advances_state_and_is_deterministic() {
    // Two consecutive decrypts must advance the key (rolling-key
    // property), and repeating the same input from the same seed
    // must produce the same trace (deterministic).
    let key0: u64 = 0xDEAD_BEEF;
    let encrypted = [0x11u8, 0x22, 0x33, 0x44];

    let mut a = OpcodeCryptor::new_with_scheme(CryptoScheme::Vmp2Rolling);
    a.set_crc(key0);
    let out_a = a.decrypt_operands(&encrypted);
    let key_after_a = a.get_crc();

    let mut b = OpcodeCryptor::new_with_scheme(CryptoScheme::Vmp2Rolling);
    b.set_crc(key0);
    let out_b = b.decrypt_operands(&encrypted);
    let key_after_b = b.get_crc();

    assert_eq!(out_a, out_b, "Vmp2 decrypt must be deterministic");
    assert_eq!(key_after_a, key_after_b);
    assert_ne!(key_after_a, key0, "rolling key must advance after decrypts");
}

#[test]
fn vmp2_round_trip_over_multi_byte_operand() {
    // Encrypt a plaintext u32 through the local encrypt helper +
    // matching key update, then decrypt via the public API. Both
    // the plaintext AND the final key must match.
    let plaintext: u32 = 0xDEAD_BEEF;
    let plain_bytes = plaintext.to_le_bytes();
    let mut mirror_key: u64 = 0x1234_5678;
    let mut encrypted = [0u8; 4];
    for (i, &b) in plain_bytes.iter().enumerate() {
        encrypted[i] = vmp2_encrypt_byte(b, mirror_key);
        mirror_key ^= b as u64;
    }

    let mut cryptor = OpcodeCryptor::new_with_scheme(CryptoScheme::Vmp2Rolling);
    cryptor.set_crc(0x1234_5678);
    let decoded = cryptor.decrypt_value_u32(&encrypted);

    assert_eq!(decoded, plaintext);
    assert_eq!(cryptor.get_crc(), mirror_key);
}

// ---------------------------------------------------------------------
// Vmp3PerHandler — same invertibility + state advancement contract
// ---------------------------------------------------------------------

/// Inverse of `decrypt_operand` for Vmp3PerHandler.
fn vmp3_encrypt_byte(plain: u8, key: u64) -> u8 {
    // Decrypt chain: XOR-key -> ROR 1 -> NOT.
    // Inverse in reverse order: NOT -> ROL 1 -> XOR-key.
    let p = !plain;
    let p = p.rotate_left(1);
    p ^ ((key & 0xFF) as u8)
}

#[test]
fn vmp3_encrypt_then_decrypt_is_identity_for_single_byte() {
    for &plain in &[0x00u8, 0x01, 0x42, 0x7F, 0x80, 0xAB, 0xFE, 0xFF] {
        for &key in &[0u64, 1, 0xFF, 0x1234_5678, 0xDEAD_BEEF_CAFE_BABE] {
            let enc = vmp3_encrypt_byte(plain, key);
            let mut c = OpcodeCryptor::new_with_scheme(CryptoScheme::Vmp3PerHandler);
            c.set_crc(key);
            let dec = c.decrypt_operand(enc, 1);
            assert_eq!(
                dec, plain,
                "Vmp3 round-trip broke: plain=0x{plain:02x} key=0x{key:x} enc=0x{enc:02x} dec=0x{dec:02x}"
            );
        }
    }
}

#[test]
fn vmp3_decrypt_advances_state_and_is_deterministic() {
    let key0: u64 = 0xCAFE_BABE;
    let encrypted = [0xAAu8, 0xBB, 0xCC, 0xDD];

    let mut a = OpcodeCryptor::new_with_scheme(CryptoScheme::Vmp3PerHandler);
    a.set_crc(key0);
    let out_a = a.decrypt_operands(&encrypted);
    let key_after_a = a.get_crc();

    let mut b = OpcodeCryptor::new_with_scheme(CryptoScheme::Vmp3PerHandler);
    b.set_crc(key0);
    let out_b = b.decrypt_operands(&encrypted);
    let key_after_b = b.get_crc();

    assert_eq!(out_a, out_b, "Vmp3 decrypt must be deterministic");
    assert_eq!(key_after_a, key_after_b);
    assert_ne!(key_after_a, key0);
}

#[test]
fn vmp3_round_trip_over_multi_byte_operand() {
    let plaintext: u64 = 0xCAFE_BABE_DEAD_BEEF;
    let plain_bytes = plaintext.to_le_bytes();
    let mut mirror_key: u64 = 0xA5A5_A5A5;
    let mut encrypted = [0u8; 8];
    for (i, &b) in plain_bytes.iter().enumerate() {
        encrypted[i] = vmp3_encrypt_byte(b, mirror_key);
        mirror_key ^= b as u64;
    }

    let mut cryptor = OpcodeCryptor::new_with_scheme(CryptoScheme::Vmp3PerHandler);
    cryptor.set_crc(0xA5A5_A5A5);
    let decoded = cryptor.decrypt_value_u64(&encrypted);

    assert_eq!(decoded, plaintext);
    assert_eq!(cryptor.get_crc(), mirror_key);
}

// ---------------------------------------------------------------------
// init_from_section — seeds the key slot on every non-None scheme
// ---------------------------------------------------------------------

#[test]
fn init_from_section_seeds_key_slot_for_every_scheme() {
    let seed = 0x1400_1234u64;
    for scheme in [
        CryptoScheme::Placeholder,
        CryptoScheme::Vmp2Rolling,
        CryptoScheme::Vmp3PerHandler,
    ] {
        let mut c = OpcodeCryptor::new_with_scheme(scheme);
        c.init_from_section(seed);
        assert_eq!(c.get_crc(), seed, "scheme {scheme:?} did not seed key from VIP");
    }

    let mut none = OpcodeCryptor::new_with_scheme(CryptoScheme::None);
    none.init_from_section(seed);
    assert_eq!(none.get_crc(), 0, "None scheme must not carry a key");
}

// ---------------------------------------------------------------------
// N-step determinism — state after N decrypts is a pure function of
// (seed, input). This is the property that lets a mid-section
// re-decode reproduce byte-for-byte.
// ---------------------------------------------------------------------

#[test]
fn n_step_state_is_deterministic_across_schemes() {
    let encrypted: Vec<u8> = (0..32).collect();
    for scheme in [
        CryptoScheme::Placeholder,
        CryptoScheme::Vmp2Rolling,
        CryptoScheme::Vmp3PerHandler,
    ] {
        let mut a = OpcodeCryptor::new_with_scheme(scheme);
        a.set_crc(0x1234);
        let out_a = a.decrypt_operands(&encrypted);
        let final_a = a.get_crc();

        let mut b = OpcodeCryptor::new_with_scheme(scheme);
        b.set_crc(0x1234);
        let out_b = b.decrypt_operands(&encrypted);
        let final_b = b.get_crc();

        assert_eq!(out_a, out_b, "{scheme:?} output not deterministic");
        assert_eq!(final_a, final_b, "{scheme:?} final state not deterministic");
    }
}
