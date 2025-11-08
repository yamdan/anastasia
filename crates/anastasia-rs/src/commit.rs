use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use ark_grumpkin::Fr as GrumpkinFr;
use bn254_blackbox_solver::{derive_generators, multi_scalar_mul};

use std::sync::LazyLock;

// From: https://github.com/noir-lang/noir/blob/075a31b4ae849374cc17a4804b1dc4976e3a3c28/acvm-repo/bn254_blackbox_solver/src/lib.rs
// > Temporary hack, this ensure that we always use a bn254 field here
// > without polluting the feature flags of the `acir_field` crate.
type FieldElement = acir::acir_field::GenericFieldElement<ark_bn254::Fr>;

pub fn derive_generators_fe(num: u32) -> Vec<FieldElement> {
    let generators = derive_generators("DEFAULT_DOMAIN_SEPARATOR".as_bytes(), num, 0);
    generators
        .iter()
        .flat_map(|g| {
            [
                FieldElement::from_repr(g.x),
                FieldElement::from_repr(g.y),
                FieldElement::from_repr(g.infinity.into()),
            ]
        })
        .collect()
}

static GENERATORS_10: LazyLock<Vec<FieldElement>> = LazyLock::new(|| derive_generators_fe(10));

pub fn compute_decomposition(x: &GrumpkinFr) -> (Fr, Fr) {
    let x_big = x.into_bigint();
    let limbs = x_big.as_ref(); // little-endian 64-bit limbs

    // Lower 128 bits = limbs[0] + limbs[1] * 2^64
    let mut low_big = <Fr as PrimeField>::BigInt::default();
    low_big.as_mut()[0] = limbs[0];
    low_big.as_mut()[1] = limbs[1];
    let low = Fr::from_bigint(low_big).unwrap();

    // Upper 128 bits = limbs[2] + limbs[3] * 2^64  (this equals (x - low) / 2^128)
    let mut high_big = <Fr as PrimeField>::BigInt::default();
    high_big.as_mut()[0] = limbs[2];
    high_big.as_mut()[1] = limbs[3];
    let high = Fr::from_bigint(high_big).unwrap();

    (low, high)
}

pub fn compute_decomposition_fe(x: &GrumpkinFr) -> (FieldElement, FieldElement) {
    let (low, high) = compute_decomposition(x);
    (FieldElement::from_repr(low), FieldElement::from_repr(high))
}

pub fn pedersen_commitment(
    scalars: &[GrumpkinFr],
    generators: Option<&[FieldElement]>,
) -> Result<(Fr, Fr, Fr), String> {
    let (scalars_lo, scalars_hi): (Vec<FieldElement>, Vec<FieldElement>) =
        scalars.iter().map(|s| compute_decomposition_fe(s)).unzip();

    let generators = match generators {
        Some(g) => g.to_vec(),
        None => derive_generators_fe(scalars.len() as u32),
    };

    let cmt = multi_scalar_mul(&generators, &scalars_lo, &scalars_hi, false)
        .map_err(|e| format!("Multi Scalar Multiplication error: {}", e))?;

    Ok((cmt.0.into_repr(), cmt.1.into_repr(), cmt.2.into_repr()))
}

/// Commit attributes using Pedersen commitment
///
/// This function takes a distinguished name (dn), key identifier (key_id), public key coordinates (pk_x, pk_y),
/// and a random value (r) to compute a Pedersen commitment.
/// It returns the commitment as a tuple of Fr elements (cmt_x, cmt_y, cmt_inf).
///
/// The dn is expected to be a 124-byte array, key_id a 20-byte array,
/// pk_x and pk_y are byte arrays representing the x and y coordinates of the public key,
/// supporting up to 48 bytes in length (to accommodate ES384 usage).
///
/// Each value is converted into a field element using 31 bytes at a time, ensuring it fits within the BN254 field.
///
/// Commitment is computed as:
///   cmt = pedersenCommit10(
///     dn[0..31],
///     dn[31..62],
///     dn[62..93],
///     dn[93..124],
///     key_id[0..20] + zero[0..11],
///     pk_x[0..31],
///     pk_x[31..48] + zero[0..14],
///     pk_y[0..31],
///     pk_y[31..48] + zero[0..14],
///     r
///   )
pub fn commit_attrs(
    dn: [u8; 124],
    key_id: &[u8],
    pk_x: &[u8],
    pk_y: &[u8],
    r: Fr, // TODO: change to GrumpkinFr
) -> Result<(Fr, Fr), String> {
    if key_id.len() != 20 {
        return Err("Key identifier must be 20 bytes".to_string());
    }
    if pk_x.len() > 48 || pk_y.len() > 48 {
        return Err("Public key coordinates must be at most 48 bytes each".to_string());
    }
    let mut pk_x_padded = [0u8; 62];
    pk_x_padded[..pk_x.len()].copy_from_slice(pk_x);
    let mut pk_y_padded = [0u8; 62];
    pk_y_padded[..pk_y.len()].copy_from_slice(pk_y);
    let mut key_id_padded = [0u8; 31];
    key_id_padded[..key_id.len()].copy_from_slice(key_id);

    let scalars = vec![
        GrumpkinFr::from_le_bytes_mod_order(&dn[0..31]),
        GrumpkinFr::from_le_bytes_mod_order(&dn[31..62]),
        GrumpkinFr::from_le_bytes_mod_order(&dn[62..93]),
        GrumpkinFr::from_le_bytes_mod_order(&dn[93..124]),
        GrumpkinFr::from_le_bytes_mod_order(&key_id_padded),
        GrumpkinFr::from_le_bytes_mod_order(&pk_x_padded[0..31]), // pk_x[0..31]
        GrumpkinFr::from_le_bytes_mod_order(&pk_x_padded[31..62]), // pk_x[31..48] + zero[0..14]
        GrumpkinFr::from_le_bytes_mod_order(&pk_y_padded[0..31]), // pk_y[0..31]
        GrumpkinFr::from_le_bytes_mod_order(&pk_y_padded[31..62]), // pk_y[31..48] + zero[0..14]
        GrumpkinFr::from_le_bytes_mod_order(&r.into_bigint().to_bytes_le()),
    ];

    let (cmt_x, cmt_y, is_infinity) = pedersen_commitment(&scalars, Some(&GENERATORS_10))?;
    if is_infinity != Fr::ZERO {
        return Err("Pedersen commitment resulted in point at infinity".to_string());
    }
    Ok((cmt_x, cmt_y))
}

#[cfg(test)]
mod tests {
    use ark_ff::{BigInteger, Field};

    use super::*;

    #[test]
    fn test_derive_generators() {
        let domain_separator = "DEFAULT_DOMAIN_SEPARATOR";
        let generators = derive_generators(domain_separator.as_bytes(), 2, 0);

        assert_eq!(
            hex::encode(generators[0].x.into_bigint().to_bytes_be()),
            "083e7911d835097629f0067531fc15cafd79a89beecb39903f69572c636f4a5a"
        );
        assert_eq!(
            hex::encode(generators[0].y.into_bigint().to_bytes_be()),
            "1a7f5efaad7f315c25a918f30cc8d7333fccab7ad7c90f14de81bcc528f9935d"
        );
        assert_eq!(
            hex::encode(generators[1].x.into_bigint().to_bytes_be()),
            "054aa86a73cb8a34525e5bbed6e43ba1198e860f5f3950268f71df4591bde402"
        );
        assert_eq!(
            hex::encode(generators[1].y.into_bigint().to_bytes_be()),
            "209dcfbf2cfb57f9f6046f44d71ac6faf87254afc7407c04eb621a6287cac126"
        );
    }

    #[test]
    fn test_pedersen_commitment() {
        let scalars = vec![
            GrumpkinFr::from(1u64),
            GrumpkinFr::from(2u64),
            GrumpkinFr::from(3u64),
            GrumpkinFr::from(4u64),
        ];
        let cmt = pedersen_commitment(&scalars, None).unwrap();

        assert_eq!(
            hex::encode(cmt.0.into_bigint().to_bytes_be()),
            "156b51f5b72a64d51d15792163d7a7de51d57184047b486782d84327c109aaf1"
        );
        assert_eq!(
            hex::encode(cmt.1.into_bigint().to_bytes_be()),
            "1ccf4c7ea35799b22b3e45d91cbc6f3087ebd09996aa9582fd6177728ee833f4"
        );
        assert_eq!(
            hex::encode(cmt.2.into_bigint().to_bytes_be()),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_compute_decomposition() {
        let x = GrumpkinFr::from(0x1234567890abcdefu64);
        let (low, high) = compute_decomposition(&x);
        assert_eq!(low, Fr::from(0x1234567890abcdefu64));
        assert_eq!(high, Fr::from(0u64));

        let x = GrumpkinFr::from(0x1234567890abcdefu64) + GrumpkinFr::from(2u64).pow([128u64]);
        let (low, high) = compute_decomposition(&x);
        assert_eq!(low, Fr::from(0x1234567890abcdefu64));
        assert_eq!(high, Fr::from(1u64));

        let x = GrumpkinFr::from(0x1234567890abcdefu64)
            + (GrumpkinFr::from(2u64).pow([128u64]) * GrumpkinFr::from(2u64));
        let (low, high) = compute_decomposition(&x);
        assert_eq!(low, Fr::from(0x1234567890abcdefu64));
        assert_eq!(high, Fr::from(2u64));
    }

    #[test]
    fn test_commit_attrs_pedersen() {
        let dn = [
            0x30, 0x29, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x47,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x4c, 0x4c, 0x43, 0x31, 0x12, 0x30, 0x10, 0x06,
            0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x44, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x43, 0x41,
            0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let key_identifier = [
            0xfe, 0x62, 0x6c, 0xdc, 0x2a, 0xe5, 0x80, 0xe7, 0x19, 0x6a, 0xca, 0x23, 0xdd, 0x23,
            0xf1, 0x39, 0x02, 0x46, 0xa8, 0xa5,
        ];
        let pk_x = [
            0x29, 0xc2, 0xef, 0x24, 0xa4, 0xbe, 0x89, 0xfd, 0x51, 0x35, 0x89, 0x24, 0xb3, 0x2e,
            0x38, 0xd2, 0x5b, 0x64, 0x9e, 0x4e, 0x96, 0xff, 0x0b, 0x6f, 0x6b, 0xe2, 0x12, 0x87,
            0x1b, 0xf5, 0x26, 0x27,
        ];
        let pk_y = [
            0x9a, 0x9d, 0x6b, 0x56, 0x68, 0x29, 0xbf, 0x3a, 0xf8, 0xfe, 0xe0, 0x50, 0x94, 0x3f,
            0xbb, 0x70, 0xab, 0xf5, 0xb1, 0xb3, 0x5a, 0xc1, 0xe3, 0xb8, 0x95, 0xee, 0x2e, 0xc0,
            0xa8, 0x5a, 0xfb, 0xd2,
        ];
        let r = Fr::from(0xdeadbeefu64);

        let (cmt_x, cmt_y) = commit_attrs(dn, &key_identifier, &pk_x, &pk_y, r).unwrap();
        let cmt_x_bytes = cmt_x.into_bigint().to_bytes_be();
        let cmt_x_hex = hex::encode(cmt_x_bytes);
        assert_eq!(
            cmt_x_hex,
            "06c54c7142201e07095430f7e9d69848e525c93c56958b22054d13f4fd98a41e"
        );
        let cmt_y_bytes = cmt_y.into_bigint().to_bytes_be();
        let cmt_y_hex = hex::encode(cmt_y_bytes);
        assert_eq!(
            cmt_y_hex,
            "0850beb53a88e53106894548cc0a40b5f8d8383679628f0a12437bec500f6483"
        );
    }
}
