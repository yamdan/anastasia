use std::sync::LazyLock;

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::Fr as GrumpkinFr;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::poseidon::get_poseidon_parameters_2;

pub static POSEIDON_CONFIG_2: LazyLock<PoseidonConfig<Fr>> =
    LazyLock::new(|| get_poseidon_parameters_2());

pub trait ToHexString {
    fn to_hex_string(&self) -> String;
}

impl ToHexString for Fr {
    fn to_hex_string(&self) -> String {
        let bytes = self.into_bigint().to_bytes_be();
        hex::encode(bytes)
    }
}

impl ToHexString for GrumpkinFr {
    fn to_hex_string(&self) -> String {
        let bytes = self.into_bigint().to_bytes_be();
        hex::encode(bytes)
    }
}

pub trait FromHexString: Sized {
    fn from_hex_string(s: &str) -> Result<Self, String>;
}

impl FromHexString for Fr {
    fn from_hex_string(s: &str) -> Result<Self, String> {
        let bytes = hex::decode(s).map_err(|_| "Failed to decode hex string".to_string())?;
        Ok(Fr::from_be_bytes_mod_order(&bytes))
    }
}

impl FromHexString for GrumpkinFr {
    fn from_hex_string(s: &str) -> Result<Self, String> {
        let bytes = hex::decode(s).map_err(|_| "Failed to decode hex string".to_string())?;
        Ok(GrumpkinFr::from_be_bytes_mod_order(&bytes))
    }
}

pub fn _field_to_base64url(v: &Fr) -> String {
    let bytes = v.into_bigint().to_bytes_be();
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn _base64url_to_field(s: &str) -> Result<Fr, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| "Failed to decode base64url string".to_string())?;
    if bytes.len() != 32 {
        return Err("Decoded bytes must be 32 bytes".to_string());
    }
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

#[derive(Debug, Clone, Copy)]
pub struct UtcTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl UtcTime {
    pub fn to_bytes(&self) -> [u8; 7] {
        let mut bytes = [0u8; 7];
        bytes[0..2].copy_from_slice(&self.year.to_be_bytes());
        bytes[2] = self.month;
        bytes[3] = self.day;
        bytes[4] = self.hour;
        bytes[5] = self.minute;
        bytes[6] = self.second;
        bytes
    }
}

pub fn to_fixed_array<const N: usize>(src: &[u8]) -> Result<[u8; N], String> {
    if src.len() > N {
        return Err(format!("input length {} exceeds {} bytes", src.len(), N));
    }
    let mut buf = [0u8; N];
    buf[..src.len()].copy_from_slice(src);
    Ok(buf)
}

pub fn from_u8_array_to_fr_vec(u8_array: &[u8]) -> Vec<Fr> {
    u8_array.iter().map(|b| Fr::from(*b as u64)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_fixed_array() {
        let src = vec![1, 2, 3, 4, 5];
        let arr: [u8; 10] = to_fixed_array(&src).unwrap();
        assert_eq!(&arr[..5], &src[..]);
        assert_eq!(&arr[5..], &[0; 5]);
    }
}
