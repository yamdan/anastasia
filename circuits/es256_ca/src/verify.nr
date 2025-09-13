use crate::{
    commit::commit_attrs,
    models::{
        authority_key_identifier_extension, basic_constraints_ca_extension, encode_length,
        key_usage_digital_signature_extension, key_usage_key_cert_sign_extension,
        subject_key_identifier_extension, UtcTime,
    },
};
use sha256::sha256_var;
use std::ecdsa_secp256r1::verify_signature;

pub fn verify<let MAX_TBS_LEN: u32, let MAX_EXT_LEN: u32>(
    issuer_pk_x: [u8; 32],
    issuer_pk_y: [u8; 32],
    sig: [u8; 64],
    serial_number: [u8; 20],
    serial_number_len: u32,
    issuer: [u8; 124],
    issuer_len: u32,
    notBefore: UtcTime,
    notAfter: UtcTime,
    now: UtcTime,
    subject: [u8; 124],
    subject_len: u32,
    subject_pk_x: [u8; 32],
    subject_pk_y: [u8; 32],
    subject_key_identifier: [u8; 20],
    authority_key_identifier: [u8; 20],
    subject_key_identifier_index: u32,
    authority_key_identifier_index: u32,
    basic_constraints_ca_index: u32,
    key_usage_key_cert_sign_index: u32,
    key_usage_digital_signature_index: u32,
    extra_extension: [u8; MAX_EXT_LEN],
    extra_extension_len: u32,
    prev_cmt: Field,
    prev_cmt_r: Field,
    next_cmt_r: Field,
) -> [Field; 1] {
    let mut buf: [u8; MAX_TBS_LEN] = [0; MAX_TBS_LEN];

    // RFC 5280, Section 4.1.2.2
    // "Given the uniqueness requirements above, serial numbers can be
    // expected to contain long integers.  Certificate users MUST be able to
    // handle serialNumber values up to 20 octets.  Conforming CAs MUST NOT
    // use serialNumber values longer than 20 octets"
    assert(serial_number_len <= 20);
    let serial_number_len_bytes: [u8; 1] = (serial_number_len as Field).to_be_bytes();

    // Time validity checks
    assert(notBefore.isBefore(now));
    assert(now.isBefore(notAfter));
    let validity_header = [0x30, 0x1e];
    let validity = validity_header.concat(notBefore.to_bytes()).concat(notAfter.to_bytes());
    let validity_len = validity.len();

    // subject public key
    let subject_public_key = [0x03, 0x42, 0x00, 0x04].concat(subject_pk_x).concat(subject_pk_y);

    // standard extensions
    let mut index = 0;
    let mut std_extensions = [0; 97]; // = 31 + 33 + 17 + 16
    let mut std_extensions_len: u32 = 0;
    for i in 1..5 {
        if i == subject_key_identifier_index {
            let ext = subject_key_identifier_extension(subject_key_identifier);
            for j in 0..31 {
                std_extensions[index] = ext[j];
                index += 1;
            }
            std_extensions_len += 31;
        } else if i == authority_key_identifier_index {
            let ext = authority_key_identifier_extension(authority_key_identifier);
            for j in 0..33 {
                std_extensions[index] = ext[j];
                index += 1;
            }
            std_extensions_len += 33;
        } else if i == basic_constraints_ca_index {
            let ext = basic_constraints_ca_extension();
            for j in 0..17 {
                std_extensions[index] = ext[j];
                index += 1;
            }
            std_extensions_len += 17;
        } else if i == key_usage_key_cert_sign_index {
            let ext = key_usage_key_cert_sign_extension();
            for j in 0..16 {
                std_extensions[index] = ext[j];
                index += 1;
            }
            std_extensions_len += 16;
        } else if i == key_usage_digital_signature_index {
            let ext = key_usage_digital_signature_extension();
            for j in 0..16 {
                std_extensions[index] = ext[j];
                index += 1;
            }
            std_extensions_len += 16;
        }
    }

    // generate chain commitment and check
    let prev_cmt_generated = commit_attrs(
        issuer,
        authority_key_identifier,
        issuer_pk_x,
        issuer_pk_y,
        prev_cmt_r,
    );
    assert(prev_cmt_generated == prev_cmt);

    let next_cmt = commit_attrs(
        subject,
        subject_key_identifier,
        subject_pk_x,
        subject_pk_y,
        next_cmt_r,
    );

    let extensions_len = std_extensions_len + extra_extension_len;
    let (extensions_seq_encoded_len, extensions_seq_encoded_len_size) =
        encode_length(extensions_len);
    let (extensions_encoded_len, extensions_encoded_len_size) =
        encode_length(extensions_len + extensions_seq_encoded_len_size + 1);

    let mut index = 0;
    let mut extensions_header = [0; 8];
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

    let sn_offset = 11;
    let sig_offset = sn_offset + serial_number_len;
    let sig_len = 12;
    let iss_offset = sig_offset + sig_len;
    let val_offset = iss_offset + issuer_len;
    let sub_offset = val_offset + validity_len;
    let spki_offset = sub_offset + subject_len;
    let spki_len = 23;
    let spk_offset = spki_offset + spki_len;
    let spk_len = 68;
    let ext_header_offset = spk_offset + spk_len;
    let std_ext_offset = ext_header_offset + extensions_header_len;
    let extra_ext_offset = std_ext_offset + std_extensions_len;
    let total_len = extra_ext_offset + extra_extension_len;

    // Length of the TBSCertificate
    let tbs_len = total_len - 4;
    assert(tbs_len >= 256);
    assert(tbs_len <= MAX_TBS_LEN);
    let tbs_len_bytes: [u8; 2] = (tbs_len as Field).to_be_bytes();

    // header
    buf[0] = 0x30;
    buf[1] = 0x82;
    buf[2] = tbs_len_bytes[0];
    buf[3] = tbs_len_bytes[1];

    // version (buf[5], ..., buf[8])
    let version = [0xa0, 0x03, 0x02, 0x01, 0x02];
    for i in 0..5 {
        buf[4 + i] = version[i];
    }

    // serial number header
    buf[9] = 0x02;
    buf[10] = serial_number_len_bytes[0];

    // signature
    let signature = [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

    // subject_public_key_info
    let subject_public_key_info = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ];

    for i in 11..MAX_TBS_LEN {
        let before_sig = i < sig_offset;
        let before_iss = i < iss_offset;
        let before_val = i < val_offset;
        let before_sub = i < sub_offset;
        let before_spki = i < spki_offset;
        let before_spk = i < spk_offset;
        let before_ext_header = i < ext_header_offset;
        let before_std_ext = i < std_ext_offset;
        let before_extra_ext = i < extra_ext_offset;
        let before_end = i < total_len;

        // serial number
        let in_sn = before_sig;
        let sn_index = if in_sn { i - sn_offset } else { 0 };
        let sn_byte = if in_sn { serial_number[sn_index] } else { 0 };

        // signature
        let in_sig = !before_sig & before_iss;
        let sig_index = if in_sig { i - sig_offset } else { 0 };
        let sig_byte = if in_sig { signature[sig_index] } else { 0 };

        // issuer
        let in_iss = !before_iss & before_val;
        let iss_index = if in_iss { i - iss_offset } else { 0 };
        let iss_byte = if in_iss { issuer[iss_index] } else { 0 };

        // validity
        let in_val = !before_val & before_sub;
        let val_index = if in_val { i - val_offset } else { 0 };
        let val_byte = if in_val { validity[val_index] } else { 0 };

        // subject
        let in_sub = !before_sub & before_spki;
        let sub_index = if in_sub { i - sub_offset } else { 0 };
        let sub_byte = if in_sub { subject[sub_index] } else { 0 };

        // subject_public_key_info
        let in_spki = !before_spki & before_spk;
        let spki_index = if in_spki { i - spki_offset } else { 0 };
        let spki_byte = if in_spki {
            subject_public_key_info[spki_index]
        } else {
            0
        };

        // subject_public_key
        let in_spk = !before_spk & before_ext_header;
        let spk_index = if in_spk { i - spk_offset } else { 0 };
        let spk_byte = if in_spk {
            subject_public_key[spk_index]
        } else {
            0
        };

        // extensions header
        let in_ext_header = !before_ext_header & before_std_ext;
        let ext_header_index = if in_ext_header {
            i - ext_header_offset
        } else {
            0
        };
        let ext_header_byte = if in_ext_header {
            extensions_header[ext_header_index]
        } else {
            0
        };

        // standard extensions
        let in_std_ext = !before_std_ext & before_extra_ext;
        let std_ext_index = if in_std_ext { i - std_ext_offset } else { 0 };
        let std_ext_byte = if in_std_ext {
            std_extensions[std_ext_index]
        } else {
            0
        };

        // extra extension
        let in_extra_ext = !before_extra_ext & before_end;
        let extra_ext_index = if in_extra_ext {
            i - extra_ext_offset
        } else {
            0
        };
        let extra_ext_byte = if in_extra_ext {
            extra_extension[extra_ext_index]
        } else {
            0
        };

        buf[i] = if before_end {
            sn_byte
                + sig_byte
                + iss_byte
                + val_byte
                + sub_byte
                + spki_byte
                + spk_byte
                + ext_header_byte
                + std_ext_byte
                + extra_ext_byte
        } else {
            0
        };
    }

    let hash = sha256_var(buf, total_len as u64);
    let result = verify_signature(issuer_pk_x, issuer_pk_y, sig, hash);
    assert(result, "Signature verification failed");

    [next_cmt]
}
