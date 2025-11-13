use std::{
    fs::File,
    io::Read,
    sync::{LazyLock, Mutex},
};

use noir::barretenberg::srs::setup_srs;
use serde_json::Value;

// pub const DEFAULT_CIRCUIT_SIZE_LIMIT: u32 = 524_288; // == 2^19 (max supported by data/default_19.srs)
pub const DEFAULT_CIRCUIT_SIZE_LIMIT: u32 = 1_048_576; // == 2^20 (max supported by data/default_20.srs)

pub struct CircuitMeta {
    pub id: String,
    pub circuit_path: String,
    pub verification_key_path: String,
    pub verification_key_keccak_mode_path: String,
    pub srs_path: String,
}

impl CircuitMeta {
    pub fn new(
        id: String,
        circuit_path: String,
        verification_key_path: String,
        verification_key_keccak_mode_path: String,
        srs_path: String,
    ) -> Self {
        Self {
            id,
            circuit_path,
            verification_key_path,
            verification_key_keccak_mode_path,
            srs_path,
        }
    }
}

pub struct Circuit {
    pub id: String,
    pub bytecode: String,
    pub verification_key: Vec<u8>,
    pub verification_key_keccak_mode: Vec<u8>,
    pub circuit_size: u32,
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
            .unwrap_or(DEFAULT_CIRCUIT_SIZE_LIMIT);

        setup_srs_from_bytecode_cached(circuit_size, &circuit_meta.srs_path)?;

        let mut vk_file =
            File::open(&circuit_meta.verification_key_path).expect("Failed to open VK file");
        let mut vk_contents = Vec::new();
        vk_file
            .read_to_end(&mut vk_contents)
            .expect("Failed to read VK file");

        let mut vk_file_keccak_mode = File::open(&circuit_meta.verification_key_keccak_mode_path)
            .expect("Failed to open VK file for keccak mode");
        let mut vk_contents_keccak_mode = Vec::new();
        vk_file_keccak_mode
            .read_to_end(&mut vk_contents_keccak_mode)
            .expect("Failed to read VK file for keccak mode");

        Ok(Self {
            id: circuit_meta.id.clone(),
            bytecode,
            circuit_size,
            verification_key: vk_contents,
            verification_key_keccak_mode: vk_contents_keccak_mode,
        })
    }
}

pub static GLOBAL_SRS: LazyLock<Mutex<Option<(u32, String)>>> = LazyLock::new(|| Mutex::new(None));

pub fn setup_srs_from_bytecode_cached(circuit_size: u32, srs_path: &str) -> Result<(), String> {
    let mut cache = GLOBAL_SRS.lock().unwrap();

    let need_reinit = match &*cache {
        Some((cached_size, cached_path))
            if *cached_size >= circuit_size && *cached_path == srs_path =>
        {
            false
        }
        _ => true,
    };

    if need_reinit {
        println!(
            "Setting up SRS for circuit size {} with path {:?}",
            circuit_size, srs_path
        );
        setup_srs(circuit_size, Some(srs_path)).map(|_| ())?;
        *cache = Some((circuit_size, srs_path.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_meta_new() {
        let meta = CircuitMeta::new(
            "es256_ca/0.1.1".to_string(),
            "data/es256_ca/0.1.1/circuit.json".to_string(),
            "data/es256_ca/0.1.1/vk".to_string(),
            "data/es256_ca/0.1.1/keccak.vk".to_string(),
            "data/default_20.srs".to_string(),
        );
        assert_eq!(meta.id, "es256_ca/0.1.1");
        assert_eq!(meta.circuit_path, "data/es256_ca/0.1.1/circuit.json");
        assert_eq!(meta.verification_key_path, "data/es256_ca/0.1.1/vk");
        assert_eq!(meta.srs_path, "data/default_20.srs");
    }

    #[test]
    fn test_circuit_new() {
        let meta = CircuitMeta::new(
            "es256_ca".to_string(),
            "data/es256_ca/0.1.1/circuit.json".to_string(),
            "data/es256_ca/0.1.1/vk".to_string(),
            "data/es256_ca/0.1.1/keccak.vk".to_string(),
            "data/default_20.srs".to_string(),
        );
        let circuit = Circuit::new(&meta).unwrap();
        assert_eq!(circuit.id, "es256_ca");
        assert!(!circuit.bytecode.is_empty());
        assert!(!circuit.verification_key.is_empty());
        assert!(circuit.circuit_size > 0);
    }
}
