package org.ethtokyo.hackathon.anastasia.data

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

@Parcelize
data class ProofGenerationResult(
    val keyAttestationJwt: String,
    val performance: ProofGenerationTime
) : Parcelable