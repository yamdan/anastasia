package org.ethtokyo.hackathon.anastasia.data

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

@Parcelize
data class ProofsGenerationResult(
    val proofs: Array<ProofResult>,
    val performances: Array<ProofGenerationTime>
) : Parcelable {
    val totalTime: Long
        get() = performances.sumOf { it.durationMs }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ProofsGenerationResult

        if (!proofs.contentEquals(other.proofs)) return false
        if (!performances.contentEquals(other.performances)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = proofs.contentHashCode()
        result = 31 * result + performances.contentHashCode()
        return result
    }
}