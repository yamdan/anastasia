use bigcurve::curves::secp384r1::{Secp384r1_Fq, Secp384r1_Fr};
use bignum::BigNum;
use noir_ecdsa::ecdsa::verify_secp384r1_ecdsa;
use sha512::sha384::sha384_var;

use es_common::{
    models::{
        prepare_extensions_header, prepare_serial_number, prepare_subject_public_key_info_es256,
        prepare_tbs, prepare_validity,
    },
    utils::UtcTime,
};

fn prepare_algorithm() -> ([u8; 12], u32) {
    let algorithm = [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
    (algorithm, algorithm.len() as u32)
}

pub fn verify_es384_256<let MAX_TBS_LEN: u32, let MAX_STD_EXT_LEN: u32, let MAX_EXTRA_EXT_LEN: u32>(
    issuer_pk_x: [u128; 4],
    issuer_pk_y: [u128; 4],
    sig_r: [u128; 4],
    sig_s: [u128; 4],
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
        prepare_extensions_header(std_extensions_len, 0);

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
    let tbs_bounded_vec = BoundedVec::<u8, MAX_TBS_LEN>::from_parts_unchecked(tbs, tbs_len);
    let hash = sha384_var(tbs_bounded_vec);

    let ipkx: Secp384r1_Fq = Secp384r1_Fq::from_limbs(issuer_pk_x);
    let ipky: Secp384r1_Fq = Secp384r1_Fq::from_limbs(issuer_pk_y);
    let sig = (Secp384r1_Fr::from_limbs(sig_r), Secp384r1_Fr::from_limbs(sig_s));

    let result = verify_secp384r1_ecdsa(ipkx, ipky, hash, sig);
    assert(result, "Signature verification failed");
}
