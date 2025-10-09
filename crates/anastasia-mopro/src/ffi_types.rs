use std::convert::TryFrom;

use uniffi::Record;

#[derive(Clone, Debug, Record)]
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
    ) -> Self {
        Self {
            id,
            circuit_path,
            verification_key_path,
            srs_path,
        }
    }
}

impl From<anastasia_rs::CircuitMeta> for CircuitMeta {
    fn from(meta: anastasia_rs::CircuitMeta) -> Self {
        CircuitMeta {
            id: meta.id,
            circuit_path: meta.circuit_path,
            verification_key_path: meta.verification_key_path,
            srs_path: meta.srs_path,
        }
    }
}

impl From<CircuitMeta> for anastasia_rs::CircuitMeta {
    fn from(meta: CircuitMeta) -> Self {
        anastasia_rs::CircuitMeta {
            id: meta.id,
            circuit_path: meta.circuit_path,
            verification_key_path: meta.verification_key_path,
            srs_path: meta.srs_path,
        }
    }
}

#[derive(Clone, Debug, Record)]
pub struct CommitResult {
    pub cmt_x: String,
    pub cmt_y: String,
    pub r: String,
}

impl From<anastasia_rs::CommitResult> for CommitResult {
    fn from(result: anastasia_rs::CommitResult) -> Self {
        CommitResult {
            cmt_x: result.cmt_x,
            cmt_y: result.cmt_y,
            r: result.r,
        }
    }
}

impl From<CommitResult> for anastasia_rs::CommitResult {
    fn from(result: CommitResult) -> Self {
        anastasia_rs::CommitResult {
            cmt_x: result.cmt_x,
            cmt_y: result.cmt_y,
            r: result.r,
        }
    }
}

#[derive(Clone, Debug, Record)]
pub struct ProofResult {
    /// The proof without public inputs
    pub proof: String,
    /// The public inputs as an array of 32-byte hex values
    pub public_inputs: Vec<String>,
    /// The number of public inputs
    pub num_public_inputs: u32,
    /// The next commitment x-coordinate
    pub next_cmt_x: String,
    /// The next commitment y-coordinate
    pub next_cmt_y: String,
    /// The random value used for the next commitment
    pub next_cmt_r: String,
}

impl From<anastasia_rs::ProofResultHex> for ProofResult {
    fn from(result: anastasia_rs::ProofResultHex) -> Self {
        ProofResult {
            proof: hex::encode(result.proof_with_public_inputs.proof),
            public_inputs: result
                .proof_with_public_inputs
                .public_inputs
                .iter()
                .map(|input| hex::encode(input))
                .collect(),
            num_public_inputs: result.proof_with_public_inputs.num_public_inputs as u32,
            next_cmt_x: result.next_cmt_x,
            next_cmt_y: result.next_cmt_y,
            next_cmt_r: result.next_cmt_r,
        }
    }
}

impl TryFrom<ProofResult> for anastasia_rs::ProofResultHex {
    type Error = hex::FromHexError;

    fn try_from(result: ProofResult) -> Result<Self, Self::Error> {
        let proof = hex::decode(&result.proof)?;
        let public_inputs = result
            .public_inputs
            .iter()
            .map(|input| hex::decode(input))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(anastasia_rs::ProofResultHex {
            proof_with_public_inputs: anastasia_rs::ProofWithPublicInputs {
                proof,
                public_inputs,
                num_public_inputs: result.num_public_inputs as usize,
            },
            next_cmt_x: result.next_cmt_x,
            next_cmt_y: result.next_cmt_y,
            next_cmt_r: result.next_cmt_r,
        })
    }
}
