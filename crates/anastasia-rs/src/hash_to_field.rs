// This file provides a Hash-to-Scalar function based on Hash-to-Field algorithms from arkworks-rs.
// It is adapted from the following source code with modifications:
// https://github.com/arkworks-rs/algebra/blob/df47f740715135b64070ca637c2cc5dc367a3405/ff/src/fields/field_hashers/mod.rs
// https://github.com/arkworks-rs/algebra/blob/df47f740715135b64070ca637c2cc5dc367a3405/ff/src/fields/field_hashers/expander/mod.rs
//
// The reason for the modifications is explained in https://github.com/arkworks-rs/algebra/issues/849:
// the original `HashToField` implementation differs in some respects from the RFC 9380 specification when using it with SHA256,
// and fixing this required changes to the implementation itself.
//
// The following fork was also used as a reference when making these changes:
// https://github.com/azixus/algebra/blob/dcf73a5f9610ba9d16a3c8e0de0b3835e5e5d5e4/ff/src/fields/field_hashers/mod.rs

use core::marker::PhantomData;
use std::sync::LazyLock;

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};
use arrayvec::ArrayVec;
use digest::{FixedOutputReset, Update, core_api::BlockSizeUser};
use sha2::Sha256;

const HASH_TO_FIELD_BN254_FR_DST: &[u8; 47] = b"QUUX-V01-CS02-with-BN254Fr_XMD:SHA-256_SSWU_RO_";

pub static HASH_TO_SCALAR: LazyLock<DefaultScalarHasher<Sha256>> = LazyLock::new(|| {
    <DefaultScalarHasher<Sha256> as HashToScalar<Fr>>::new(HASH_TO_FIELD_BN254_FR_DST)
});

pub trait Expander {
    fn expand(&self, msg: &[u8], length: usize) -> Vec<u8>;
}
const MAX_DST_LENGTH: usize = 255;

const LONG_DST_PREFIX: &[u8; 17] = b"H2C-OVERSIZE-DST-";

struct DST(arrayvec::ArrayVec<u8, MAX_DST_LENGTH>);

impl DST {
    pub fn new_xmd<H: FixedOutputReset + Default>(dst: &[u8]) -> DST {
        let array = if dst.len() > MAX_DST_LENGTH {
            let mut long = H::default();
            long.update(&LONG_DST_PREFIX[..]);
            long.update(&dst);
            ArrayVec::try_from(long.finalize_fixed().as_ref()).unwrap()
        } else {
            ArrayVec::try_from(dst).unwrap()
        };
        DST(array)
    }

    pub fn update<H: Update>(&self, h: &mut H) {
        h.update(self.0.as_ref());
        // I2OSP(len,1) https://www.rfc-editor.org/rfc/rfc8017.txt
        h.update(&[self.0.len() as u8]);
    }
}

struct ExpanderXmd<H: FixedOutputReset + Default + Clone> {
    hasher: PhantomData<H>,
    dst: Vec<u8>,
    block_size: usize,
}

static Z_PAD: [u8; 256] = [0u8; 256];

impl<H: FixedOutputReset + Default + Clone> Expander for ExpanderXmd<H> {
    fn expand(&self, msg: &[u8], n: usize) -> Vec<u8> {
        use digest::typenum::Unsigned;
        // output size of the hash function, e.g. 32 bytes = 256 bits for sha2::Sha256
        let b_len = H::OutputSize::to_usize();
        let ell = (n + (b_len - 1)) / b_len;
        assert!(
            ell <= 255,
            "The ratio of desired output to the output size of hash function is too large!"
        );

        let dst_prime = DST::new_xmd::<H>(self.dst.as_ref());
        // Represent `len_in_bytes` as a 2-byte array.
        // As per I2OSP method outlined in https://tools.ietf.org/pdf/rfc8017.pdf,
        // The program should abort if integer that we're trying to convert is too large.
        assert!(n < (1 << 16), "Length should be smaller than 2^16");
        let lib_str: [u8; 2] = (n as u16).to_be_bytes();

        let mut hasher = H::default();
        hasher.update(&Z_PAD[0..self.block_size]);
        hasher.update(msg);
        hasher.update(&lib_str);
        hasher.update(&[0u8]);
        dst_prime.update(&mut hasher);
        let b0 = hasher.finalize_fixed_reset();

        hasher.update(&b0);
        hasher.update(&[1u8]);
        dst_prime.update(&mut hasher);
        let mut bi = hasher.finalize_fixed_reset();

        let mut uniform_bytes: Vec<u8> = Vec::with_capacity(n);
        uniform_bytes.extend_from_slice(&bi);
        for i in 2..=ell {
            // update the hasher with xor of b_0 and b_i elements
            for (l, r) in b0.iter().zip(bi.iter()) {
                hasher.update(&[*l ^ *r]);
            }
            hasher.update(&[i as u8]);
            dst_prime.update(&mut hasher);
            bi = hasher.finalize_fixed_reset();
            uniform_bytes.extend_from_slice(&bi);
        }
        uniform_bytes.truncate(n);
        uniform_bytes
    }
}

/// Trait for hashing messages to scalar.
pub trait HashToScalar<F: Field>: Sized {
    /// Initialises a new hash-to-scalar helper struct.
    ///
    /// # Arguments
    ///
    /// * `domain` - bytes that get concatenated with the `msg` during hashing, in order to separate potentially interfering instantiations of the hasher.
    fn new(domain: &[u8]) -> Self;

    /// Hash an arbitrary `msg` to an element of the field `F`.
    fn hash_to_scalar(&self, msg: &[u8]) -> F;
}

/// This scalar hasher constructs a Hash-To-Scalar based on a fixed-output hash function,
/// like SHA2, SHA3 or Blake2.
/// The implementation aims to follow the specification in [The BBS Signature Scheme - 4.2.2. Hash to Scalar](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-hash-to-scalar).
///
/// # Examples
///
/// ```
/// use ark_ff::fields::field_hashers::{DefaultFieldHasher, HashToField};
/// use ark_test_curves::bls12_381::Fq;
/// use sha2::Sha256;
///
/// let hasher = <DefaultFieldHasher<Sha256> as HashToField<Fq>>::new(&[1, 2, 3]);
/// let field_elements: [Fq; 2] = hasher.hash_to_field(b"Hello, World!");
///
/// assert_eq!(field_elements.len(), 2);
/// ```
pub struct DefaultScalarHasher<H: FixedOutputReset + Default + Clone, const SEC_PARAM: usize = 128>
{
    expander: ExpanderXmd<H>,
    len_per_base_elem: usize,
}

impl<F: Field, H: FixedOutputReset + BlockSizeUser + Default + Clone, const SEC_PARAM: usize>
    HashToScalar<F> for DefaultScalarHasher<H, SEC_PARAM>
{
    fn new(dst: &[u8]) -> Self {
        // The final output of `hash_to_field` will be an array of field
        // elements from F::BaseField, each of size `len_per_elem`.
        let len_per_base_elem = get_len_per_elem::<F, SEC_PARAM>();

        let expander = ExpanderXmd {
            hasher: PhantomData,
            dst: dst.to_vec(),
            block_size: H::block_size(),
        };

        DefaultScalarHasher {
            expander,
            len_per_base_elem,
        }
    }

    fn hash_to_scalar(&self, message: &[u8]) -> F {
        let uniform_bytes = self.expander.expand(message, self.len_per_base_elem);

        F::from_base_prime_field(F::BasePrimeField::from_be_bytes_mod_order(&uniform_bytes))
    }
}

/// This function computes the length in bytes that a hash function should output
/// for hashing an element of type `Field`.
/// See section 5.1 and 5.3 of the
/// [IETF hash standardization draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/14/)
const fn get_len_per_elem<F: Field, const SEC_PARAM: usize>() -> usize {
    // ceil(log(p))
    let base_field_size_in_bits = F::BasePrimeField::MODULUS_BIT_SIZE as usize;
    // ceil(log(p)) + security_parameter
    let base_field_size_with_security_padding_in_bits = base_field_size_in_bits + SEC_PARAM;
    // ceil( (ceil(log(p)) + security_parameter) / 8)
    let bytes_per_base_field_elem =
        ((base_field_size_with_security_padding_in_bits + 7) / 8) as u64;
    bytes_per_base_field_elem as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_scalar_bls12381_sha_256() {
        // test vectors from:
        // <https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-map-messages-to-scalars-2>
        // <https://github.com/decentralized-identity/bbs-signature/blob/bbc09290c2b4034672ac887bd809028b2c33067b/tooling/fixtures/fixture_data/bls12-381-sha-256/MapMessageToScalarAsHash.json>

        use ark_ff::BigInteger;
        use ark_test_curves::bls12_381::Fr;
        use hex::FromHex;
        use sha2::Sha256;

        let dst = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_MAP_MSG_TO_SCALAR_AS_HASH_";
        let dst = dst.as_bytes();
        let hasher = <DefaultScalarHasher<Sha256> as HashToScalar<Fr>>::new(&dst);

        let msgs = [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
            "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
            "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
            "496694774c5604ab1b2544eababcf0f53278ff50",
            "515ae153e22aae04ad16f759e07237b4",
            "d183ddc6e2665aa4e2f088af",
            "ac55fb33a75909ed",
            "96012096",
            "",
        ];

        let expected_scalars = [
            "1cb5bb86114b34dc438a911617655a1db595abafac92f47c5001799cf624b430",
            "154249d503c093ac2df516d4bb88b510d54fd97e8d7121aede420a25d9521952",
            "0c7c4c85cdab32e6fdb0de267b16fa3212733d4e3a3f0d0f751657578b26fe22",
            "4a196deafee5c23f630156ae13be3e46e53b7e39094d22877b8cba7f14640888",
            "34c5ea4f2ba49117015a02c711bb173c11b06b3f1571b88a2952b93d0ed4cf7e",
            "4045b39b83055cd57a4d0203e1660800fabe434004dbdc8730c21ce3f0048b08",
            "064621da4377b6b1d05ecc37cf3b9dfc94b9498d7013dc5c4a82bf3bb1750743",
            "34ac9196ace0a37e147e32319ea9b3d8cc7d21870d3c3ba071246859cca49b02",
            "57eb93f417c43200e9784fa5ea5a59168d3dbc38df707a13bb597c871b2a5f74",
            "08e3afeb2b4f2b5f907924ef42856616e6f2d5f1fb373736db1cca32707a7d16",
        ];

        let msgs = msgs.map(|msg| Vec::from_hex(msg).expect("Failed to decode hex string"));
        let scalars: Vec<Fr> = msgs.map(|msg| hasher.hash_to_scalar(&msg)).into();

        let scalars_hex = scalars.iter().map(|scalar| {
            scalar
                .into_bigint()
                .to_bytes_be()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        });

        let expected_scalars: Vec<String> =
            expected_scalars.iter().map(|s| s.to_string()).collect();

        assert_eq!(
            scalars_hex.collect::<Vec<_>>(),
            expected_scalars,
            "Hash to scalar test failed"
        );
    }
}
