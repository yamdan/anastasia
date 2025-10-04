package org.ethtokyo.hackathon.anastasia.ui.smartcontractcompleted

data class ProofVerificationResult(
    val proofIndex: Int,
    val isSuccess: Boolean,
    val smartContractAddress: String,
    val response: String,
    val error: String
)