use std::ecdsa_secp256r1::verify_signature;

use es_common::{
    models::{
        prepare_extensions_header, prepare_serial_number, prepare_subject_public_key_info_es256,
        prepare_tbs, prepare_validity,
    },
    utils::UtcTime,
};
use sha256::sha256_var;

fn prepare_algorithm() -> ([u8; 12], u32) {
    let algorithm = [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    (algorithm, algorithm.len() as u32)
}

pub fn verify_es256_256<let MAX_TBS_LEN: u32, let MAX_STD_EXT_LEN: u32, let MAX_EXTRA_EXT_LEN: u32>(
    issuer_pk_x: [u8; 32],
    issuer_pk_y: [u8; 32],
    sig: [u8; 64],
    serial_number: [u8; 20],
    serial_number_len: u32,
    issuer: [u8; 124],
    issuer_len: u32,
    subject: [u8; 124],
    subject_len: u32,
    subject_pk_x: [u8; 32],
    subject_pk_y: [u8; 32],
    std_extensions: [u8; MAX_STD_EXT_LEN],
    std_extensions_len: u32,
    extra_extension: [u8; MAX_EXTRA_EXT_LEN],
    extra_extension_len: u32,
    not_before: [u8; 7],
    not_after: [u8; 7],
    now: [u8; 7],
) {
    // version
    let version = [0xa0, 0x03, 0x02, 0x01, 0x02];
    let version_len = 5;

    // serial number
    let (serial_number, serial_number_len) =
        prepare_serial_number(serial_number, serial_number_len);

    // signature
    let (signature, signature_len) = prepare_algorithm();

    // validity
    let not_before = UtcTime::from_bytes(not_before);
    let not_after = UtcTime::from_bytes(not_after);
    let now = UtcTime::from_bytes(now);
    let (validity, validity_len) = prepare_validity(not_before, not_after, now);

    // subject_public_key_info
    let (subject_public_key_info, subject_public_key_info_len) =
        prepare_subject_public_key_info_es256(subject_pk_x, subject_pk_y);

    // Prepare extensions header
    let (extensions_header, extensions_header_len) =
        prepare_extensions_header(std_extensions_len, extra_extension_len);

    // Prepare tbsCertificate
    let (tbs, tbs_len): ([_; MAX_TBS_LEN], _) = prepare_tbs(
        version,
        version_len,
        serial_number,
        serial_number_len,
        signature,
        signature_len,
        issuer,
        issuer_len,
        validity,
        validity_len,
        subject,
        subject_len,
        subject_public_key_info,
        subject_public_key_info_len,
        extensions_header,
        extensions_header_len,
        std_extensions,
        std_extensions_len,
        extra_extension,
        extra_extension_len,
    );

    // Verify signature
    let hash = sha256_var(tbs, tbs_len as u64);
    let result = verify_signature(issuer_pk_x, issuer_pk_y, sig, hash);
    assert(result, "Signature verification failed");
}
