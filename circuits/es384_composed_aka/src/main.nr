use es256_common::check_nyms;

global SUBJECT_LEN_CA: u32 = 65; // TODO: adjust subject length
global MAX_EXTRA_EXT_LEN_CA: u32 = 30;
global MAX_EXTRA_EXT_LEN_EE: u32 = 500;

fn main(
    // public inputs
    now: pub [u8; 7],
    root_pk_x: pub [u8; 48],
    root_pk_y: pub [u8; 48],
    root_key_identifier: pub [u8; 20],
    context: pub Field,
    nym: pub Field,
    // for subroot (Droid CA3)
    sig_subroot: [u8; 96],
    serial_number_subroot: [u8; 20],
    serial_number_len_subroot: u32,
    subject_pk_x_subroot: [u8; 32],
    subject_pk_y_subroot: [u8; 32],
    not_before_subroot: [u8; 7],
    not_after_subroot: [u8; 7],
    subject_key_identifier_subroot: [u8; 20],
    // for ca (StrongBox)
    sig_ca: [u8; 64],
    serial_number_ca: [u8; 20],
    serial_number_len_ca: u32,
    subject_ca: [u8; SUBJECT_LEN_CA],
    subject_pk_x_ca: [u8; 32],
    subject_pk_y_ca: [u8; 32],
    extra_extension_ca: [u8; MAX_EXTRA_EXT_LEN_CA],
    extra_extension_len_ca: u32,
    not_before_ca: [u8; 7],
    not_after_ca: [u8; 7],
    subject_key_identifier_ca: [u8; 20],
    // for ee (Android Key Store)
    sig_ee: [u8; 64],
    subject_pk_x_ee: [u8; 32],
    subject_pk_y_ee: [u8; 32],
    extra_extension_ee: [u8; MAX_EXTRA_EXT_LEN_EE],
    extra_extension_len_ee: u32,
    not_before_ee: [u8; 7],
    not_after_ee: [u8; 7],
    user_sk: Field,
) {
    // Verify subroot cert
    es384_droid_ca3::verify(
        root_pk_x,
        root_pk_y,
        sig_subroot,
        serial_number_subroot,
        serial_number_len_subroot,
        subject_pk_x_subroot,
        subject_pk_y_subroot,
        subject_key_identifier_subroot,
        root_key_identifier,
        not_before_subroot,
        not_after_subroot,
        now,
    );

    // Verify ca cert
    es256_strongbox::verify(
        subject_pk_x_subroot,
        subject_pk_y_subroot,
        sig_ca,
        serial_number_ca,
        serial_number_len_ca,
        subject_ca,
        subject_pk_x_ca,
        subject_pk_y_ca,
        subject_key_identifier_ca,
        subject_key_identifier_subroot,
        extra_extension_ca,
        extra_extension_len_ca,
        not_before_ca,
        not_after_ca,
        now,
    );

    // Verify ee cert
    es256_keystore::verify(
        subject_pk_x_ca,
        subject_pk_y_ca,
        sig_ee,
        subject_ca,
        subject_pk_x_ee,
        subject_pk_y_ee,
        extra_extension_ee,
        extra_extension_len_ee,
        not_before_ee,
        not_after_ee,
        now,
    );

    // Verify pseudonym
    check_nyms(subject_pk_x_ee, subject_pk_y_ee, user_sk, context, nym);
}
