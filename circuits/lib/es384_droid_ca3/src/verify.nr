use bigcurve::curves::secp384r1::{Secp384r1_Fq, Secp384r1_Fr};
use bignum::BigNum;
use noir_ecdsa::ecdsa::verify_secp384r1_ecdsa;
use sha512::sha384::sha384_var;

use crate::models::prepare_tbs;
use es_common::{
    models::{prepare_serial_number, prepare_subject_public_key_info_es256, prepare_validity},
    utils::{to_bignum_limbs, UtcTime},
};

pub fn verify(
    issuer_pk_x: [u8; 48],
    issuer_pk_y: [u8; 48],
    sig: [u8; 96],
    serial_number: [u8; 20],
    serial_number_len: u32,
    subject_pk_x: [u8; 32],
    subject_pk_y: [u8; 32],
    subject_key_identifier: [u8; 20],
    authority_key_identifier: [u8; 20],
    not_before: [u8; 7],
    not_after: [u8; 7],
    now: [u8; 7],
) {
    // serial number
    let (serial_number, serial_number_len) =
        prepare_serial_number(serial_number, serial_number_len);

    // validity
    let not_before = UtcTime::from_bytes(not_before);
    let not_after = UtcTime::from_bytes(not_after);
    let now = UtcTime::from_bytes(now);
    let (validity, _validity_len) = prepare_validity(not_before, not_after, now);

    // subject_public_key_info
    let (subject_public_key_info, _subject_public_key_info_len) =
        prepare_subject_public_key_info_es256(subject_pk_x, subject_pk_y);

    // Prepare tbsCertificate
    let (tbs, tbs_len) = prepare_tbs(
        serial_number,
        serial_number_len,
        validity,
        subject_public_key_info,
        subject_key_identifier,
        authority_key_identifier,
    );

    // Verify signature
    let tbs_bounded_vec = BoundedVec::<u8, _>::from_parts_unchecked(tbs, tbs_len);
    let hash = sha384_var(tbs_bounded_vec);

    let ipkx: Secp384r1_Fq = Secp384r1_Fq::from_limbs(to_bignum_limbs(issuer_pk_x));
    let ipky: Secp384r1_Fq = Secp384r1_Fq::from_limbs(to_bignum_limbs(issuer_pk_y));
    let mut sig_r = [0u8; 48];
    let mut sig_s = [0u8; 48];
    for i in 0..48 {
        sig_r[i] = sig[i];
        sig_s[i] = sig[48 + i];
    }
    let sig = (
        Secp384r1_Fr::from_limbs(to_bignum_limbs(sig_r)),
        Secp384r1_Fr::from_limbs(to_bignum_limbs(sig_s)),
    );

    let result = verify_secp384r1_ecdsa(ipkx, ipky, hash, sig);
    assert(result, "Signature verification failed");
}
