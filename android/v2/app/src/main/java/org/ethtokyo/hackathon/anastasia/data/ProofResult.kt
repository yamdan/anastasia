package org.ethtokyo.hackathon.anastasia.data

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

@Parcelize
data class ProofResult(
    val proofForEE: Boolean,
    val proof: String,
    val publicInputs: List<String>,
    val numPublicInputs: UInt,
    val nextCmtX: String,
    val nextCmtY: String,
    val nextCmtR: String
) : Parcelable