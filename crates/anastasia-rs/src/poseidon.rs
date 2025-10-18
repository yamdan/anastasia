mod config;
mod crh;

pub use config::get_poseidon_parameters_2;
pub use crh::CRH;

use std::sync::LazyLock;

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;

pub static POSEIDON_CONFIG_2: LazyLock<PoseidonConfig<Fr>> =
    LazyLock::new(|| get_poseidon_parameters_2());
