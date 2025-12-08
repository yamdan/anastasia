use es_common::{
    concat::meta_concat_chunks,
    models::{
        key_usage_digital_signature_extension, prepare_subject_public_key_info_es256,
        prepare_validity,
    },
    utils::{encode_length, encode_length_3, UtcTime},
};

global HEADER_LEN: u32 = 4;
global VERSION_LEN: u32 = 5;
global SERIAL_NUMBER_LEN: u32 = 3;
global SIGNATURE_LEN: u32 = 12;
pub global ISSUER_LEN: u32 = 65; // TODO: adjust length
global SUBJECT_LEN: u32 = 33;
global VALIDITY_LEN: u32 = 32;
global SPKI_LEN: u32 = 91;
global MAX_EXT_HEADER_LEN: u32 = 8;
global STD_EXT_LEN: u32 = 16;
pub global MAX_EXTRA_EXT_LEN: u32 = 500;

// Chunk 0: header, version, serial number, signature, issuer, validity, subject, subject_public_key_info, *extensions header*
global MIN_LEN_0: u32 = HEADER_LEN
    + VERSION_LEN
    + SERIAL_NUMBER_LEN
    + SIGNATURE_LEN
    + ISSUER_LEN
    + VALIDITY_LEN
    + SUBJECT_LEN
    + SPKI_LEN;
global MAX_LEN_0: u32 = MIN_LEN_0 + MAX_EXT_HEADER_LEN;

// Chunk 1: standard extensions, *extra extension*
global MIN_LEN_1: u32 = STD_EXT_LEN;
global MAX_LEN_1: u32 = MIN_LEN_1 + MAX_EXTRA_EXT_LEN;

global MAX_TBS_LEN: u32 = MAX_LEN_0 + MAX_LEN_1;

// version = v3
global VERSION: [u8; VERSION_LEN] = [0xa0, 0x03, 0x02, 0x01, 0x02];

// Serial number
global SERIAL_NUMBER: [u8; SERIAL_NUMBER_LEN] = [0x02, 0x01, 0x01];

// signature = ecdsa-with-SHA256
global SIGNATURE: [u8; SIGNATURE_LEN] =
    [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

// subject = "CN=Android Keystore Key"
global SUBJECT: [u8; SUBJECT_LEN] = [
    0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x14, 0x41, 0x6e, 0x64,
    0x72, 0x6f, 0x69, 0x64, 0x20, 0x4b, 0x65, 0x79, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x20, 0x4b, 0x65,
    0x79,
];

pub fn prepare_std_extensions() -> [u8; STD_EXT_LEN] {
    let mut index = 0;
    let mut std_extensions = [0; STD_EXT_LEN];

    let ext = key_usage_digital_signature_extension();
    for j in 0..16 {
        std_extensions[index] = ext[j];
        index += 1;
    }

    assert(index == STD_EXT_LEN, "Standard extensions length mismatch");
    std_extensions
}

pub fn prepare_extensions_header(
    std_extensions_len: u32,
    extra_extension_len: u32,
) -> ([u8; MAX_EXT_HEADER_LEN], u32) {
    let extensions_len = std_extensions_len + extra_extension_len;
    let (extensions_seq_encoded_len, extensions_seq_encoded_len_size) =
        encode_length(extensions_len);
    let (extensions_encoded_len, extensions_encoded_len_size) =
        encode_length(extensions_len + extensions_seq_encoded_len_size + 1);

    let mut index = 0;
    let mut extensions_header = [0; MAX_EXT_HEADER_LEN];
    extensions_header[index] = 0xa3;
    index += 1;
    for i in 0..3 {
        if i < extensions_encoded_len_size {
            extensions_header[index] = extensions_encoded_len[i];
            index += 1;
        }
    }
    extensions_header[index] = 0x30;
    index += 1;
    for i in 0..3 {
        if i < extensions_seq_encoded_len_size {
            extensions_header[index] = extensions_seq_encoded_len[i];
            index += 1;
        }
    }
    let extensions_header_len = index;

    assert(extensions_header_len <= MAX_EXT_HEADER_LEN, "Extensions header length exceeds maximum");

    (extensions_header, extensions_header_len)
}

pub fn reserialize(
    issuer: [u8; ISSUER_LEN],
    subject_pk_x: [u8; 32],
    subject_pk_y: [u8; 32],
    extra_extension: [u8; MAX_EXTRA_EXT_LEN],
    extra_extension_len: u32,
    not_before: [u8; 7],
    not_after: [u8; 7],
    now: [u8; 7],
) -> ([u8; MAX_TBS_LEN], u32) {
    // Prepare validity
    let not_before = UtcTime::from_bytes(not_before);
    let not_after = UtcTime::from_bytes(not_after);
    let now = UtcTime::from_bytes(now);
    let (validity, _validity_len) = prepare_validity(not_before, not_after, now);

    // Prepare subject_public_key_info
    let (subject_public_key_info, _subject_public_key_info_len) =
        prepare_subject_public_key_info_es256(subject_pk_x, subject_pk_y);

    // Prepare extensions header
    let (extensions_header, extensions_header_len) =
        prepare_extensions_header(STD_EXT_LEN, extra_extension_len);

    // Prepare standard extensions
    let std_extensions = prepare_std_extensions();

    // Calculate tbs length
    let tbs_len = 4
        + VERSION_LEN
        + SERIAL_NUMBER_LEN
        + SIGNATURE_LEN
        + ISSUER_LEN
        + VALIDITY_LEN
        + SUBJECT_LEN
        + SPKI_LEN
        + extensions_header_len
        + STD_EXT_LEN
        + extra_extension_len;
    assert(tbs_len <= MAX_TBS_LEN, "tbsCertificate length exceeds MAX_TBS_LEN");
    let tbs_value_len = tbs_len - 4;
    // Assume tbsCertificate length fits in 2 bytes
    assert(tbs_value_len >= 256);
    assert(tbs_value_len <= 65535);
    let tbs_len_bytes = encode_length_3(tbs_value_len);

    // Chunk 0: header, version, serial number, signature, issuer, validity, subject, subject_public_key_info, extensions header
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
    // serial number
    for i in 0..SERIAL_NUMBER_LEN {
        chunk_0_bytes[chunk_0_index] = SERIAL_NUMBER[i];
        chunk_0_index += 1;
    }
    // signature
    for i in 0..SIGNATURE_LEN {
        chunk_0_bytes[chunk_0_index] = SIGNATURE[i];
        chunk_0_index += 1;
    }
    // issuer
    for i in 0..ISSUER_LEN {
        chunk_0_bytes[chunk_0_index] = issuer[i];
        chunk_0_index += 1;
    }
    // validity
    for i in 0..VALIDITY_LEN {
        chunk_0_bytes[chunk_0_index] = validity[i];
        chunk_0_index += 1;
    }
    // subject
    for i in 0..SUBJECT_LEN {
        chunk_0_bytes[chunk_0_index] = SUBJECT[i];
        chunk_0_index += 1;
    }
    // subject_public_key_info
    for i in 0..SPKI_LEN {
        chunk_0_bytes[chunk_0_index] = subject_public_key_info[i];
        chunk_0_index += 1;
    }
    // *extensions header* (variable length)
    for i in 0..MAX_LEN_0 - MIN_LEN_0 {
        chunk_0_bytes[chunk_0_index] = if i < extensions_header_len {
            extensions_header[i]
        } else {
            0
        };
        chunk_0_index += 1;
    }

    let boundary_0 = MIN_LEN_0 + extensions_header_len;

    // Chunk 1: standard extensions, extra extension
    let mut chunk_1_index = 0;
    let mut chunk_1_bytes = [0; MAX_TBS_LEN - MIN_LEN_0];
    // standard extensions
    for i in 0..STD_EXT_LEN {
        chunk_1_bytes[chunk_1_index] = std_extensions[i];
        chunk_1_index += 1;
    }
    // *extra extension* (variable length)
    for i in 0..MAX_LEN_1 - MIN_LEN_1 {
        chunk_1_bytes[chunk_1_index] = if i < extra_extension_len {
            extra_extension[i]
        } else {
            0
        };
        chunk_1_index += 1;
    }

    println("es256_strongbox::models::prepare_tbs debug info:");

    let buf = meta_concat_chunks!([MIN_LEN_0], [MAX_LEN_0], MAX_TBS_LEN)(
        chunk_0_bytes,
        chunk_1_bytes,
        [boundary_0]
    );

    (buf, tbs_len)
}
