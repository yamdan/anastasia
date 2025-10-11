use ark_bn254::Fr;
use ark_crypto_primitives::crh::CRHScheme;
use ark_ff::{PrimeField, Zero};

use crate::poseidon::{CRH, POSEIDON_CONFIG_2};

fn compress_ecdsa_pk(pk: &([u8; 32], [u8; 32])) -> [u8; 33] {
    let (x, y) = pk;
    let y_is_even = y[31] & 1 == 0;
    let prefix = if y_is_even { 0x02 } else { 0x03 };
    let mut compressed = [0u8; 33];
    compressed[0] = prefix;
    compressed[1..].copy_from_slice(x);
    compressed
}

fn hash_ecdsa_pk_to_scalar(pk: &([u8; 32], [u8; 32])) -> Result<Fr, String> {
    let compressed = compress_ecdsa_pk(pk);
    if compressed.len() != 33 {
        return Err("Compressed ECDSA public key must be 33 bytes".to_string());
    }
    if compressed[0] != 0x02 && compressed[0] != 0x03 {
        return Err("Invalid ECDSA public key prefix, must be 0x02 or 0x03".to_string());
    }

    let first_17_bytes = &compressed[0..17];
    let last_16_bytes = &compressed[17..33];
    let first_17_bytes_fr = Fr::from_be_bytes_mod_order(first_17_bytes);
    let last_16_bytes_fr = Fr::from_be_bytes_mod_order(last_16_bytes);

    let scalar = CRH::<Fr>::evaluate(&*POSEIDON_CONFIG_2, [first_17_bytes_fr, last_16_bytes_fr])
        .expect("Failed to evaluate Poseidon hash");
    Ok(scalar)
}

fn generate_device_user_sk(user_sk: &Fr, device_pk: &([u8; 32], [u8; 32])) -> Result<Fr, String> {
    let device_pk_field = hash_ecdsa_pk_to_scalar(device_pk)
        .map_err(|e| format!("Failed to hash device public key: {}", e))?;

    let device_user_sk = CRH::<Fr>::evaluate(&*POSEIDON_CONFIG_2, [*user_sk, device_pk_field])
        .map_err(|_| "Failed to evaluate Poseidon hash for user device secret key".to_string())?;

    Ok(device_user_sk)
}

pub fn generate_nym(
    user_sk: &Fr,
    device_pk: &([u8; 32], [u8; 32]),
    context: &Fr,
) -> Result<Fr, String> {
    let device_user_sk = generate_device_user_sk(user_sk, device_pk)
        .map_err(|e| format!("Failed to generate device user private key: {}", e))?;

    let nym = CRH::<Fr>::evaluate(&*POSEIDON_CONFIG_2, [device_user_sk, *context])
        .map_err(|e| format!("Failed to evaluate nym: {}", e))?;

    if nym.is_zero() {
        return Err("Generated nym is zero".to_string());
    }

    Ok(nym)
}
