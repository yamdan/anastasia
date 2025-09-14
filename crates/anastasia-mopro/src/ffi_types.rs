use uniffi::Record;

#[derive(Clone, Debug, Record)]
pub struct CircuitMeta {
    pub id: String,
    pub circuit_path: String,
    pub verification_key_path: String,
    pub srs_path: String,
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
    pub cmt: String,
    pub r: String,
}

impl From<anastasia_rs::CommitResult> for CommitResult {
    fn from(result: anastasia_rs::CommitResult) -> Self {
        CommitResult {
            cmt: result.cmt,
            r: result.r,
        }
    }
}

impl From<CommitResult> for anastasia_rs::CommitResult {
    fn from(result: CommitResult) -> Self {
        anastasia_rs::CommitResult {
            cmt: result.cmt,
            r: result.r,
        }
    }
}

#[derive(Clone, Debug, Record)]
pub struct ProofResult {
    pub proof: String,
    pub next_cmt: String,
    pub next_cmt_r: String,
}

impl From<anastasia_rs::ProofResult> for ProofResult {
    fn from(result: anastasia_rs::ProofResult) -> Self {
        ProofResult {
            proof: hex::encode(result.proof),
            next_cmt: result.next_cmt,
            next_cmt_r: result.next_cmt_r,
        }
    }
}

impl From<ProofResult> for anastasia_rs::ProofResult {
    fn from(result: ProofResult) -> Self {
        anastasia_rs::ProofResult {
            proof: hex::decode(result.proof).unwrap(), // TODO: handle error
            next_cmt: result.next_cmt,
            next_cmt_r: result.next_cmt_r,
        }
    }
}
