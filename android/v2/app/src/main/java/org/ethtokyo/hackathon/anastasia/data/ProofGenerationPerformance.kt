package org.ethtokyo.hackathon.anastasia.data

import android.os.Parcelable
import kotlinx.parcelize.Parcelize


@Parcelize
data class ProofGenerationTime(
    val startTime: Long,
    val endTime: Long,
    val durationMs: Long
) : Parcelable {
    fun toFormattedString(): String {
        val sb = StringBuilder()
        sb.append("\ntotal time: ${durationMs / 1000.0} sec")
        return sb.toString()
    }
}