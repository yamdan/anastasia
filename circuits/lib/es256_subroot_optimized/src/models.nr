use es_common::{
    concat::concat_chunks,
    models::{MAX_STD_CA_EXTENSIONS_LEN, SUBJECT_PUBLIC_KEY_INFO_LEN, VALIDITY_LEN},
};

pub global MAX_TBS_LEN: u32 = 549;
pub global MAX_EXTRA_EXT_LEN: u32 = 30;

pub fn prepare_tbs_optimized(
    version: [u8; 5],
    serial_number: [u8; 22],
    serial_number_len: u32,
    signature: [u8; 12],
    issuer: [u8; 124],
    issuer_len: u32,
    validity: [u8; 32],
    subject: [u8; 124],
    subject_len: u32,
    subject_public_key_info: [u8; 91],
    extensions_header: [u8; 8],
    extensions_header_len: u32,
    std_extensions: [u8; MAX_STD_CA_EXTENSIONS_LEN],
    extra_extension: [u8; MAX_EXTRA_EXT_LEN],
    extra_extension_len: u32,
) -> ([u8; MAX_TBS_LEN], u32) {
    let version_offset = 4;
    let serial_number_offset = version_offset + 5;
    let signature_offset = serial_number_offset + serial_number_len;
    let issuer_offset = signature_offset + 12;
    let validity_offset = issuer_offset + issuer_len;
    let subject_offset = validity_offset + VALIDITY_LEN;
    let subject_public_key_info_offset = subject_offset + subject_len;
    let ext_header_offset = subject_public_key_info_offset + SUBJECT_PUBLIC_KEY_INFO_LEN;
    let std_ext_offset = ext_header_offset + extensions_header_len;
    let extra_ext_offset = std_ext_offset + MAX_STD_CA_EXTENSIONS_LEN;
    let tbs_len = extra_ext_offset + extra_extension_len;
    assert(tbs_len <= MAX_TBS_LEN, "tbsCertificate length exceeds MAX_TBS_LEN");

    let tbs_value_len = tbs_len - 4;
    // Assume tbsCertificate length fits in 2 bytes
    assert(tbs_value_len >= 256);
    assert(tbs_value_len <= 65535);
    let tbs_len_bytes: [u8; 2] = (tbs_value_len as Field).to_be_bytes();

    let mut buf: [u8; MAX_TBS_LEN] = [0; MAX_TBS_LEN];

    // chunk 0: header, version, serial number
    // min: 9 + 3, max: 9 + 22
    let mut chunk_0 = [0; 9 + 22];
    chunk_0[0] = 0x30;
    chunk_0[1] = 0x82;
    chunk_0[2] = tbs_len_bytes[0];
    chunk_0[3] = tbs_len_bytes[1];
    for i in 0..5 {
        chunk_0[4 + i] = version[i];
    }
    for i in 0..22 {
        chunk_0[9 + i] = serial_number[i];
    }
    let chunk_0_len = 9 + serial_number_len;

    // chunk 1: signature, issuer
    // min: 12 + 1, max: 12 + 124
    let mut chunk_1 = [0; 12 + 124];
    for i in 0..12 {
        chunk_1[i] = signature[i];
    }
    for i in 0..124 {
        chunk_1[12 + i] = issuer[i];
    }
    let chunk_1_len = 12 + issuer_len;

    // chunk 2: validity, subject
    // min: VALIDITY_LEN + 1, max: VALIDITY_LEN + 124
    let mut chunk_2 = [0; VALIDITY_LEN + 124];
    for i in 0..VALIDITY_LEN {
        chunk_2[i] = validity[i];
    }
    for i in 0..124 {
        chunk_2[VALIDITY_LEN + i] = subject[i];
    }
    let chunk_2_len = VALIDITY_LEN + subject_len;

    // chunk 3: subject public key info, extensions header
    // min: SUBJECT_PUBLIC_KEY_INFO_LEN + 2, max: SUBJECT_PUBLIC_KEY_INFO_LEN + 8
    let mut chunk_3 = [0; SUBJECT_PUBLIC_KEY_INFO_LEN + 8];
    for i in 0..SUBJECT_PUBLIC_KEY_INFO_LEN {
        chunk_3[i] = subject_public_key_info[i];
    }
    for i in 0..8 {
        chunk_3[SUBJECT_PUBLIC_KEY_INFO_LEN + i] = extensions_header[i];
    }
    let chunk_3_len = SUBJECT_PUBLIC_KEY_INFO_LEN + extensions_header_len;

    // chunk 4: standard extensions, extra extension
    // min: MAX_STD_CA_EXTENSIONS_LEN + 0, max: MAX_STD_CA_EXTENSIONS_LEN + MAX_EXTRA_EXT_LEN
    let mut chunk_4 = [0; MAX_STD_CA_EXTENSIONS_LEN + MAX_EXTRA_EXT_LEN];
    for i in 0..MAX_STD_CA_EXTENSIONS_LEN {
        chunk_4[i] = std_extensions[i];
    }
    for i in 0..MAX_EXTRA_EXT_LEN {
        chunk_4[MAX_STD_CA_EXTENSIONS_LEN + i] = extra_extension[i];
    }
    let chunk_4_len = MAX_STD_CA_EXTENSIONS_LEN + extra_extension_len;

    // calculate tbs_len and tbs_len_bytes
    let all_chunks_len = chunk_0_len + chunk_1_len + chunk_2_len + chunk_3_len + chunk_4_len;
    assert(all_chunks_len == tbs_len, "tbsCertificate length mismatch");

    let buf = concat_chunks!([
        (9 + 3, 9 + 22),
        (12 + 1, 12 + 124),
        (VALIDITY_LEN + 1, VALIDITY_LEN + 124),
        (SUBJECT_PUBLIC_KEY_INFO_LEN + 2, SUBJECT_PUBLIC_KEY_INFO_LEN + 8),
        (MAX_STD_CA_EXTENSIONS_LEN + 0, MAX_STD_CA_EXTENSIONS_LEN + MAX_EXTRA_EXT_LEN),
    ])(
        chunk_0,
        chunk_1,
        chunk_2,
        chunk_3,
        chunk_4,
        [chunk_0_len, chunk_1_len, chunk_2_len, chunk_3_len],
    );

    (buf, all_chunks_len)
}
