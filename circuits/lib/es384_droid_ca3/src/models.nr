use es_common::{
    concat::concat_chunks,
    models::{
        authority_key_identifier_extension, basic_constraints_ca_extension,
        key_usage_key_cert_sign_extension, prepare_serial_number,
        prepare_subject_public_key_info_es256, prepare_validity, subject_key_identifier_extension,
    },
    utils::{encode_length_1, encode_length_3, UtcTime},
};

global HEADER_LEN: u32 = 4;
global VERSION_LEN: u32 = 5;
global MAX_SERIAL_NUMBER_LEN: u32 = 20;
global MAX_ENCODED_SERIAL_NUMBER_LEN: u32 = MAX_SERIAL_NUMBER_LEN + 2;
global SIGNATURE_LEN: u32 = 12;
global ISSUER_LEN: u32 = 43;
global SUBJECT_LEN: u32 = 43;
global VALIDITY_LEN: u32 = 32;
global SPKI_LEN: u32 = 91;
global EXT_HEADER_LEN: u32 = 4;
global STD_EXT_LEN: u32 = 97; // 31 + 33 + 17 + 16
global KEY_IDENTIFIER_LEN: u32 = 20;
global MAX_EXTRA_EXT_LEN: u32 = 0;

// Chunk 0: header, version, *serial number*
global MIN_LEN_0: u32 = HEADER_LEN + VERSION_LEN;
global MAX_LEN_0: u32 = MIN_LEN_0 + MAX_ENCODED_SERIAL_NUMBER_LEN;

// Chunk 1: signature, issuer, validity, subject, subject_public_key_info, extensions header, standard extensions, *extra extension*
global MIN_LEN_1: u32 = SIGNATURE_LEN
    + ISSUER_LEN
    + VALIDITY_LEN
    + SUBJECT_LEN
    + SPKI_LEN
    + EXT_HEADER_LEN
    + STD_EXT_LEN;
global MAX_LEN_1: u32 = MIN_LEN_1 + MAX_EXTRA_EXT_LEN;

global MAX_TBS_LEN: u32 = MAX_LEN_0 + MAX_LEN_1;

// version = v3
global VERSION: [u8; VERSION_LEN] = [0xa0, 0x03, 0x02, 0x01, 0x02];

// signature = ecdsa-with-SHA384
global SIGNATURE: [u8; SIGNATURE_LEN] =
    [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];

// issuer = "O=Google LLC, CN=Droid CA2"
global ISSUER: [u8; ISSUER_LEN] = [
    0x30, 0x29, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x47, 0x6f, 0x6f,
    0x67, 0x6c, 0x65, 0x20, 0x4c, 0x4c, 0x43, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x13, 0x09, 0x44, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x43, 0x41, 0x32,
];

// subject = "O=Google LLC, CN=Droid CA3"
global SUBJECT: [u8; SUBJECT_LEN] = [
    0x30, 0x29, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x47, 0x6f, 0x6f,
    0x67, 0x6c, 0x65, 0x20, 0x4c, 0x4c, 0x43, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x13, 0x09, 0x44, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x43, 0x41, 0x33,
];

// Prepare extensions header
global EXTENSIONS_HEADER: [u8; EXT_HEADER_LEN] =
    [0xa3, encode_length_1(STD_EXT_LEN + 2), 0x30, encode_length_1(STD_EXT_LEN)];

pub fn prepare_std_extensions(
    subject_key_identifier: [u8; KEY_IDENTIFIER_LEN],
    authority_key_identifier: [u8; KEY_IDENTIFIER_LEN],
) -> [u8; STD_EXT_LEN] {
    let mut index = 0;
    let mut std_extensions = [0; STD_EXT_LEN];

    let ext = key_usage_key_cert_sign_extension();
    for j in 0..16 {
        std_extensions[index] = ext[j];
        index += 1;
    }
    let ext = basic_constraints_ca_extension();
    for j in 0..17 {
        std_extensions[index] = ext[j];
        index += 1;
    }
    let ext = subject_key_identifier_extension(subject_key_identifier);
    for j in 0..31 {
        std_extensions[index] = ext[j];
        index += 1;
    }
    let ext = authority_key_identifier_extension(authority_key_identifier);
    for j in 0..33 {
        std_extensions[index] = ext[j];
        index += 1;
    }

    assert(index == STD_EXT_LEN, "Standard extensions length mismatch");
    std_extensions
}

pub fn reserialize(
    serial_number: [u8; MAX_SERIAL_NUMBER_LEN],
    serial_number_len: u32,
    subject_pk_x: [u8; 32],
    subject_pk_y: [u8; 32],
    subject_key_identifier: [u8; KEY_IDENTIFIER_LEN],
    authority_key_identifier: [u8; KEY_IDENTIFIER_LEN],
    not_before: [u8; 7],
    not_after: [u8; 7],
    now: [u8; 7],
) -> ([u8; MAX_TBS_LEN], u32) {
    // Prepare serial number
    let (serial_number, serial_number_len) =
        prepare_serial_number(serial_number, serial_number_len);

    // Prepare validity
    let not_before = UtcTime::from_bytes(not_before);
    let not_after = UtcTime::from_bytes(not_after);
    let now = UtcTime::from_bytes(now);
    let (validity, _validity_len) = prepare_validity(not_before, not_after, now);

    // Prepare subject_public_key_info
    let (subject_public_key_info, _subject_public_key_info_len) =
        prepare_subject_public_key_info_es256(subject_pk_x, subject_pk_y);

    // Prepare standard extensions
    let std_extensions = prepare_std_extensions(subject_key_identifier, authority_key_identifier);

    // Calculate tbs length
    let tbs_len = 4
        + VERSION_LEN
        + serial_number_len
        + SIGNATURE_LEN
        + ISSUER_LEN
        + VALIDITY_LEN
        + SUBJECT_LEN
        + SPKI_LEN
        + EXT_HEADER_LEN
        + STD_EXT_LEN;
    assert(tbs_len <= MAX_TBS_LEN, "tbsCertificate length exceeds MAX_TBS_LEN");
    let tbs_value_len = tbs_len - 4;
    // Assume tbsCertificate length fits in 2 bytes
    assert(tbs_value_len >= 256);
    assert(tbs_value_len <= 65535);
    let tbs_len_bytes = encode_length_3(tbs_value_len);

    // Chunk 0: header, version, serial number
    let mut chunk_0_index = 0;
    let mut chunk_0_bytes = [0; MAX_LEN_0];
    // header
    chunk_0_bytes[0] = 0x30;
    chunk_0_index += 1;
    for i in 0..3 {
        chunk_0_bytes[chunk_0_index] = tbs_len_bytes[i];
        chunk_0_index += 1;
    }
    // version
    for i in 0..VERSION_LEN {
        chunk_0_bytes[chunk_0_index] = VERSION[i];
        chunk_0_index += 1;
    }
    // *serial number* (variable length)
    for i in 0..MAX_LEN_0 - MIN_LEN_0 {
        chunk_0_bytes[chunk_0_index] = if i < serial_number_len {
            serial_number[i]
        } else {
            0
        };
        chunk_0_index += 1;
    }

    let boundary_0 = MIN_LEN_0 + serial_number_len;

    // Chunk 1: signature, issuer, validity, subject, subject_public_key_info, extensions header
    let mut chunk_1_index = 0;
    let mut chunk_1_bytes = [0; MAX_TBS_LEN - MIN_LEN_0];
    // signature
    for i in 0..SIGNATURE_LEN {
        chunk_1_bytes[chunk_1_index] = SIGNATURE[i];
        chunk_1_index += 1;
    }
    // issuer
    for i in 0..ISSUER_LEN {
        chunk_1_bytes[chunk_1_index] = ISSUER[i];
        chunk_1_index += 1;
    }
    // validity
    for i in 0..VALIDITY_LEN {
        chunk_1_bytes[chunk_1_index] = validity[i];
        chunk_1_index += 1;
    }
    // subject
    for i in 0..SUBJECT_LEN {
        chunk_1_bytes[chunk_1_index] = SUBJECT[i];
        chunk_1_index += 1;
    }
    // subject_public_key_info
    for i in 0..SPKI_LEN {
        chunk_1_bytes[chunk_1_index] = subject_public_key_info[i];
        chunk_1_index += 1;
    }
    // extensions header
    for i in 0..EXT_HEADER_LEN {
        chunk_1_bytes[chunk_1_index] = EXTENSIONS_HEADER[i];
        chunk_1_index += 1;
    }
    // standard extensions
    for i in 0..STD_EXT_LEN {
        chunk_1_bytes[chunk_1_index] = std_extensions[i];
        chunk_1_index += 1;
    }

    println("es384_droid_ca3::models::prepare_tbs debug info:");

    let buf = concat_chunks!([MIN_LEN_0], [MAX_LEN_0], MAX_TBS_LEN)(
        chunk_0_bytes,
        chunk_1_bytes,
        [boundary_0]
    );

    (buf, tbs_len)
}
