use std::ecdsa_secp256r1::verify_signature;

use es256_common::check_nyms;

fn main(
    hash: pub [u8; 32],
    context: pub Field,
    nym: pub Field,
    sig: [u8; 64],
    pk_x: [u8; 32],
    pk_y: [u8; 32],
    user_sk: Field,
) {
    // Verify signature
    let result = verify_signature(pk_x, pk_y, sig, hash);
    assert(result, "Signature verification failed");

    // Verify pseudonym
    check_nyms(pk_x, pk_y, user_sk, context, nym);
}
