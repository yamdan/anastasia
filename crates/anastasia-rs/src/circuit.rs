use std::{
    fs::File,
    io::Read,
    sync::{LazyLock, Mutex},
};

use noir::barretenberg::{srs::setup_srs, utils::get_circuit_size};
use serde_json::Value;

pub struct CircuitMeta {
    pub id: String,
    pub circuit_path: String,
    pub verification_key_path: String,
    pub srs_path: String,
}

impl CircuitMeta {
    pub fn new(
        id: String,
        circuit_path: String,
        verification_key_path: String,
        srs_path: String,
    ) -> Result<Self, String> {
        Ok(CircuitMeta {
            id,
            circuit_path,
            verification_key_path,
            srs_path,
        })
    }
}

pub struct Circuit {
    pub id: String,
    pub bytecode: String,
    pub verification_key: Vec<u8>,
    pub circuit_size: u32,
    pub public_input_size: Option<u64>,
    pub max_extra_extension_len: usize,
}

impl Circuit {
    pub fn new(circuit_meta: &CircuitMeta) -> Result<Self, String> {
        let mut circuit_file =
            File::open(&circuit_meta.circuit_path).expect("Failed to open JSON file");
        let mut contents = String::new();
        circuit_file
            .read_to_string(&mut contents)
            .expect("Failed to read JSON file");
        let v: Value = serde_json::from_str(&contents).expect("Failed to parse JSON");

        let bytecode = v["bytecode"]
            .as_str()
            .expect("No 'bytecode' property found")
            .to_string();

        let circuit_size = v["circuit_size"]
            .as_u64()
            .map(|v| v as u32)
            .unwrap_or_else(|| get_circuit_size(&bytecode, false));

        let public_input_size = v["public_input_size"].as_u64();

        let max_extra_extension_len = v["max_extra_extension_len"]
            .as_u64()
            .map(|v| v as usize)
            .unwrap_or(128);

        setup_srs_from_bytecode_cached(circuit_size, &circuit_meta.srs_path)?;

        let mut vk_file =
            File::open(&circuit_meta.verification_key_path).expect("Failed to open VK file");
        let mut vk_contents = Vec::new();
        vk_file
            .read_to_end(&mut vk_contents)
            .expect("Failed to read VK file");

        Ok(Self {
            id: circuit_meta.id.clone(),
            bytecode,
            circuit_size,
            public_input_size,
            max_extra_extension_len,
            verification_key: vk_contents,
        })
    }
}

pub static GLOBAL_SRS: LazyLock<Mutex<Option<u32>>> = LazyLock::new(|| Mutex::new(None));

fn setup_srs_from_bytecode_cached(circuit_size: u32, srs_path: &str) -> Result<(), String> {
    let mut cache = GLOBAL_SRS.lock().unwrap();

    let need_reinit = match &*cache {
        Some(cached_size) if *cached_size >= circuit_size => false,
        _ => true,
    };

    if need_reinit {
        println!(
            "Setting up SRS for circuit size {} with path {:?}",
            circuit_size, srs_path
        );
        setup_srs(circuit_size, Some(srs_path)).map(|_| ())?;
        *cache = Some(circuit_size);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_meta_new() {
        let meta = CircuitMeta::new(
            "es256_ca".to_string(),
            "data/es256_ca.json".to_string(),
            "data/es256_ca.vk".to_string(),
            "data/common.srs".to_string(),
        )
        .unwrap();
        assert_eq!(meta.id, "es256_ca");
        assert_eq!(meta.circuit_path, "data/es256_ca.json");
        assert_eq!(meta.verification_key_path, "data/es256_ca.vk");
        assert_eq!(meta.srs_path, "data/common.srs");
    }

    #[test]
    fn test_circuit_new() {
        let meta = CircuitMeta::new(
            "es256_ca".to_string(),
            "data/es256_ca.json".to_string(),
            "data/es256_ca.vk".to_string(),
            "data/common.srs".to_string(),
        )
        .unwrap();
        let circuit = Circuit::new(&meta).unwrap();
        assert_eq!(circuit.id, "es256_ca");
        assert!(!circuit.bytecode.is_empty());
        assert!(!circuit.verification_key.is_empty());
        assert!(circuit.circuit_size > 0);
        //assert!(circuit.public_input_size.is_some());
        assert!(circuit.max_extra_extension_len > 0);
    }
}
