use es256_common::{check_commitments, check_nyms, prepare_std_ee_extensions, verify_es256_256};

global MAX_TBS_LEN: u32 = 700;
global MAX_EXTRA_EXT_LEN: u32 = 500;

fn main(
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
    extra_extension: [u8; MAX_EXTRA_EXT_LEN],
    extra_extension_len: u32,
    not_before: [u8; 7],
    not_after: [u8; 7],
    now: pub [u8; 7],
    prev_cmt: pub (Field, Field),
    prev_cmt_r: Field,
    given_authority_key_identifier: [u8; 20],
    user_sk: Field,
    context: pub Field,
    nym: pub Field,
) {
    // Verify previous chain commitment
    let mut issuer_pk_x_padded = [0; 48];
    for i in 0..32 {
        issuer_pk_x_padded[i] = issuer_pk_x[i];
    }
    let mut issuer_pk_y_padded = [0; 48];
    for i in 0..32 {
        issuer_pk_y_padded[i] = issuer_pk_y[i];
    }
    check_commitments(
        issuer,
        given_authority_key_identifier,
        issuer_pk_x_padded,
        issuer_pk_y_padded,
        prev_cmt,
        prev_cmt_r,
    );

    // Verify pseudonym
    check_nyms(subject_pk_x, subject_pk_y, user_sk, context, nym);

    // Prepare standard extensions
    let (std_extensions, std_extensions_len) = prepare_std_ee_extensions();

    // Verify signature
    verify_es256_256::<MAX_TBS_LEN, _, _>(
        issuer_pk_x,
        issuer_pk_y,
        sig,
        serial_number,
        serial_number_len,
        issuer,
        issuer_len,
        subject,
        subject_len,
        subject_pk_x,
        subject_pk_y,
        std_extensions,
        std_extensions_len,
        extra_extension,
        extra_extension_len,
        not_before,
        not_after,
        now,
    )
}
