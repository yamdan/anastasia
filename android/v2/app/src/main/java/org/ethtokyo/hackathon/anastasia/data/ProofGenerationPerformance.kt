package org.ethtokyo.hackathon.anastasia.data

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

@Parcelize
data class ProofGenerationPerformance(
    val individualTimes: List<ProofGenerationTime>,
    val totalTime: Long
) : Parcelable {
    fun toFormattedString(): String {
        val sb = StringBuilder()

        individualTimes.forEachIndexed { index, time ->
            sb.append("proof ${index + 1} generation: ${time.durationMs / 1000.0} sec\n")
        }

        sb.append("\ntotal time: ${totalTime / 1000.0} sec")
        return sb.toString()
    }
}

@Parcelize
data class ProofGenerationTime(
    val proofIndex: Int,
    val startTime: Long,
    val endTime: Long,
    val durationMs: Long
) : Parcelable