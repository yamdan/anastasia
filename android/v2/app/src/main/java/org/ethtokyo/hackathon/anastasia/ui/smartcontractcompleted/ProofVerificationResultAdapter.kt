package org.ethtokyo.hackathon.anastasia.ui.smartcontractcompleted

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import org.ethtokyo.hackathon.anastasia.R
import org.json.JSONObject

class ProofVerificationResultAdapter(
    private val proofVerificationResults: List<ProofVerificationResult>
) : RecyclerView.Adapter<ProofVerificationResultAdapter.ProofResultViewHolder>() {

    class ProofResultViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val proofNumber: TextView = itemView.findViewById(R.id.textView_proof_number)
        val status: TextView = itemView.findViewById(R.id.textView_status)
        val smartContract: TextView = itemView.findViewById(R.id.textView_smart_contract)
        val details: TextView = itemView.findViewById(R.id.textView_details)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ProofResultViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_proof_verification_result, parent, false)
        return ProofResultViewHolder(view)
    }

    override fun onBindViewHolder(holder: ProofResultViewHolder, position: Int) {
        val proofResult = proofVerificationResults[position]

        holder.proofNumber.text = "Proof ${proofResult.proofIndex + 1}"
        holder.status.text = if (proofResult.isSuccess) "✅ Success" else "❌ Failed"
        holder.smartContract.text = "SmartContract: ${proofResult.smartContractAddress}"

        // Detailsの表示
        val detailsText = if (proofResult.isSuccess && proofResult.response.isNotEmpty()) {
            formatResponsePreview(proofResult.response)
        } else if (!proofResult.isSuccess) {
            buildString {
                if (proofResult.error.isNotEmpty()) {
                    append(proofResult.error)
                }
                if (proofResult.response.isNotEmpty()) {
                    if (proofResult.error.isNotEmpty()) {
                        append("\n\n")
                    }
                    append(formatResponsePreview(proofResult.response))
                }
                if (isEmpty()) {
                    append("No details available")
                }
            }
        } else {
            "No details available"
        }

        holder.details.text = detailsText
    }

    override fun getItemCount(): Int = proofVerificationResults.size

    private fun formatResponsePreview(response: String): String {
        val limit = 250
        val jsonLimit = 200
        return try {
            if (response.isBlank()) return "Empty response"

            val json = JSONObject(response)

            if (json.has("result")) {
                val result = json.get("result").toString()
                if (result.length > limit) {
                    "${result.take(limit)}..."
                } else {
                    result
                }
            } else if (json.has("id") || json.has("jsonrpc")) {
                "JSON-RPC Response: ${if (response.length > jsonLimit) response.take(jsonLimit) + "..." else response}"
            } else {
                if (response.length > limit) {
                    "${response.take(limit)}..."
                } else {
                    response
                }
            }

        } catch (e: Exception) {
            if (response.length > limit) {
                "${response.take(limit)}..."
            } else {
                response
            }
        }
    }
}