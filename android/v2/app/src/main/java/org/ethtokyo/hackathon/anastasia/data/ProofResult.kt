package org.ethtokyo.hackathon.anastasia.data

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

@Parcelize
data class ProofResult(
    val proofForEE: Boolean,
    val proof: String,
    val nextCmt: String,
    val nextCmtR: String
) : Parcelable