use poseidon::poseidon::bn254::hash_2;

pub fn compress_ecdsa_pk(x: [u8; 32], y: [u8; 32]) -> [u8; 33] {
    let mut out: [u8; 33] = [0; 33];
    out[0] = if y[31] & 1 == 0 { 0x02 } else { 0x03 };
    for i in 0..32 {
        out[i + 1] = x[i];
    }
    out
}

pub fn compute_device_public_key_field(pk_x: [u8; 32], pk_y: [u8; 32]) -> Field {
    let device_public_key_compressed = compress_ecdsa_pk(pk_x, pk_y);

    // The first 17 bytes of the compressed public key
    let mut device_public_key_field_1: Field = 0;
    for i in 0..17 {
        device_public_key_field_1 =
            device_public_key_field_1 * 256 + (device_public_key_compressed[i] as Field);
    }

    // The last 16 bytes of the compressed public key
    let mut device_public_key_field_2: Field = 0;
    for i in 17..33 {
        device_public_key_field_2 =
            device_public_key_field_2 * 256 + (device_public_key_compressed[i] as Field);
    }

    let device_public_key_field = hash_2([device_public_key_field_1, device_public_key_field_2]);
    device_public_key_field
}

pub fn generate_nym(
    pk_x: [u8; 32],
    pk_y: [u8; 32],
    user_private_key: Field,
    context: Field,
) -> Field {
    let device_public_key_field = compute_device_public_key_field(pk_x, pk_y);
    let user_device_private_key = hash_2([user_private_key, device_public_key_field]);
    let nym = hash_2([user_device_private_key, context]);
    nym
}
