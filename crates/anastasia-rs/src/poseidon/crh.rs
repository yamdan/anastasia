//! This implementation modifies the standard [Arkworks Poseidon hash](https://github.com/arkworks-rs/crypto-primitives/blob/f8e3383f9a937b48de84b6f656de7f6211946fb8/crypto-primitives/src/crh/poseidon/mod.rs) to match the conventions used in Noir and Circom:
//! - During absorb, capacity elements are prepended (added to the front) of the input.
//! - During squeeze, capacity elements are appended (rather than prepended) of the output.
//! This ensures compatibility with Noir and Circom Poseidon hash circuits, which differ from the default Arkworks behavior.

use ark_crypto_primitives::{
    Error,
    crh::{CRHScheme, TwoToOneCRHScheme},
    sponge::{
        Absorb, CryptographicSponge,
        poseidon::{PoseidonConfig, PoseidonSponge},
    },
};
use ark_ff::PrimeField;
use ark_std::{borrow::Borrow, marker::PhantomData, rand::Rng};

pub struct CRH<F: PrimeField + Absorb> {
    field_phantom: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHScheme for CRH<F> {
    type Input = [F];
    type Output = F;
    type Parameters = PoseidonConfig<F>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        // automatic generation of parameters are not implemented yet
        // therefore, the developers must specify the parameters themselves
        unimplemented!()
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let input = input.borrow();

        // Pad zeros equal to the capacity at the beginning of the input (not at the end)
        let mut padded_input = Vec::with_capacity(parameters.capacity + input.len());
        for _ in 0..parameters.capacity {
            padded_input.push(F::zero());
        }
        padded_input.extend_from_slice(input);

        // Set capacity to zero here to ensure that, as in Noir and Circom, the output is taken from the beginning of the final state.
        // This matches the convention where the first elements of the state (after permutation) are used as the output,
        // rather than skipping capacity elements as in the default Arkworks implementation.
        let mut modified_parameters = parameters.clone();
        modified_parameters.rate = parameters.rate + parameters.capacity;
        modified_parameters.capacity = 0;

        let mut sponge = PoseidonSponge::new(&modified_parameters);
        sponge.absorb(&padded_input);
        let res = sponge.squeeze_field_elements::<F>(1);
        Ok(res[0])
    }
}

pub struct TwoToOneCRH<F: PrimeField + Absorb> {
    field_phantom: PhantomData<F>,
}

impl<F: PrimeField + Absorb> TwoToOneCRHScheme for TwoToOneCRH<F> {
    type Input = F;
    type Output = F;
    type Parameters = PoseidonConfig<F>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        // automatic generation of parameters are not implemented yet
        // therefore, the developers must specify the parameters themselves
        unimplemented!()
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        Self::compress(parameters, left_input, right_input)
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        let left_input = left_input.borrow();
        let right_input = right_input.borrow();

        // Pad zeros equal to the capacity at the beginning of the input (not at the end)
        let mut padded_input = Vec::with_capacity(parameters.capacity);
        for _ in 0..parameters.capacity {
            padded_input.push(F::zero());
        }

        // Set capacity to zero here to ensure that, as in Noir and Circom, the output is taken from the beginning of the final state.
        // This matches the convention where the first elements of the state (after permutation) are used as the output,
        // rather than skipping capacity elements as in the default Arkworks implementation.
        let mut modified_parameters = parameters.clone();
        modified_parameters.rate = parameters.rate + parameters.capacity;
        modified_parameters.capacity = 0;

        let mut sponge = PoseidonSponge::new(&modified_parameters);
        sponge.absorb(&padded_input); // Absorb the padded input first
        sponge.absorb(left_input);
        sponge.absorb(right_input);
        let res = sponge.squeeze_field_elements::<F>(1);
        Ok(res[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::get_poseidon_parameters_2;
    use ark_bn254::Fr;
    use ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        sponge::{CryptographicSponge, FieldBasedCryptographicSponge, poseidon::PoseidonSponge},
    };
    use ark_std::str::FromStr;

    #[test]
    fn test_poseidon_2() {
        // Parameters and test vectors are taken from:
        // https://extgit.isec.tugraz.at/krypto/hadeshash/-/blob/master/code/test_vectors.txt

        let poseidon_config_2 = get_poseidon_parameters_2();

        let l = Fr::from(1u64);
        let r = Fr::from(2u64);
        let h = TwoToOneCRH::<Fr>::evaluate(&poseidon_config_2, &l, &r)
            .expect("Failed to evaluate leaf hash");

        assert_eq!(
            h,
            Fr::from_str(
                // 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
                "7853200120776062878684798364095072458815029376092732009249414926327459813530"
            )
            .unwrap()
        );

        let h = CRH::<Fr>::evaluate(&poseidon_config_2, [Fr::from(1), Fr::from(2)])
            .expect("Failed to evaluate leaf hash");

        assert_eq!(
            h,
            Fr::from_str(
                // 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
                "7853200120776062878684798364095072458815029376092732009249414926327459813530"
            )
            .unwrap()
        );

        // Create a new PoseidonConfig with modified rate and capacity, keeping other fields the same
        let mut modified_parameters = poseidon_config_2.clone();
        modified_parameters.rate = poseidon_config_2.rate + poseidon_config_2.capacity;
        modified_parameters.capacity = 0;
        let mut poseidon_sponge = PoseidonSponge::<Fr>::new(&modified_parameters);
        poseidon_sponge.absorb(&vec![Fr::from(0), Fr::from(1), Fr::from(2)]);
        //        poseidon_sponge.absorb(&vec![Fr::from(0), Fr::from(1), Fr::from(2)]);
        let res = poseidon_sponge.squeeze_native_field_elements(3);
        assert_eq!(
            res,
            vec![
                Fr::from_str(
                    // 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
                    "7853200120776062878684798364095072458815029376092732009249414926327459813530"
                )
                .unwrap(),
                Fr::from_str(
                    // 0x0fca49b798923ab0239de1c9e7a4a9a2210312b6a2f616d18b5a87f9b628ae29
                    "7142104613055408817911962100316808866448378443474503659992478482890339429929"
                )
                .unwrap(),
                Fr::from_str(
                    // 0x0e7ae82e40091e63cbd4f16a6d16310b3729d4b6e138fcf54110e2867045a30c
                    "6549537674122432311777789598043107870002137484850126429160507761192163713804"
                )
                .unwrap()
            ]
        );
    }
}
