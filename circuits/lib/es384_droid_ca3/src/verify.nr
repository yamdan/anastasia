use bigcurve::curves::secp384r1::{Secp384r1_Fq, Secp384r1_Fr};
use bignum::BigNum;
use noir_ecdsa::ecdsa::verify_secp384r1_ecdsa;
use sha512::sha384::sha384_var;

use crate::models::prepare_tbs;
use es_common::utils::to_bignum_limbs;

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
    // Re-Serialize
    let (tbs, tbs_len) = prepare_tbs(
        serial_number,
        serial_number_len,
        subject_pk_x,
        subject_pk_y,
        subject_key_identifier,
        authority_key_identifier,
        not_before,
        not_after,
        now,
    );

    // Hash
    let tbs_bounded_vec = BoundedVec::<u8, _>::from_parts_unchecked(tbs, tbs_len);
    let hash = sha384_var(tbs_bounded_vec);

    // Verify signature
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
