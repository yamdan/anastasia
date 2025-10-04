package org.ethtokyo.hackathon.anastasia.ui.smartcontractcompleted

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import androidx.navigation.fragment.navArgs
import androidx.recyclerview.widget.LinearLayoutManager
import org.ethtokyo.hackathon.anastasia.R
import org.ethtokyo.hackathon.anastasia.databinding.FragmentSmartContractCompletedBinding
import org.json.JSONObject

class SmartContractCompletedFragment : Fragment() {

    private var _binding: FragmentSmartContractCompletedBinding? = null
    private val binding get() = _binding!!
    private val args: SmartContractCompletedFragmentArgs by navArgs()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentSmartContractCompletedBinding.inflate(inflater, container, false)

        // JSONデータをパースして表示
        parseAndDisplayResults(args.responseData)

        binding.buttonFinish.setOnClickListener {
            findNavController().navigate(R.id.action_smartContractCompletedFragment_to_navigation_key_management)
        }

        return binding.root
    }

    private fun parseAndDisplayResults(jsonData: String) {
        try {
            val json = JSONObject(jsonData)
            val resultsArray = json.getJSONArray("results")

            // ProofResultリストを作成
            val proofVerificationResults = mutableListOf<ProofVerificationResult>()
            var successCount = 0
            var failedCount = 0

            for (i in 0 until resultsArray.length()) {
                val result = resultsArray.getJSONObject(i)
                val proofIndex = result.getInt("proofIndex")
                val isSuccess = result.getBoolean("isSuccess")
                val smartContractAddress = result.optString("smartContractAddress", "N/A")
                val response = result.optString("response", "")
                val error = result.optString("error", "")

                proofVerificationResults.add(
                    ProofVerificationResult(
                        proofIndex = proofIndex,
                        isSuccess = isSuccess,
                        smartContractAddress = smartContractAddress,
                        response = response,
                        error = error
                    )
                )

                if (isSuccess) {
                    successCount++
                } else {
                    failedCount++
                }
            }

            // Summaryを表示
            binding.textViewSuccessfulCount.text = "Successful: $successCount"
            binding.textViewFailedCount.text = "Failed: $failedCount"
            binding.textViewTotalCount.text = "Total proofs: ${proofVerificationResults.size}"

            // RecyclerViewを設定
            binding.recyclerViewProofs.layoutManager = LinearLayoutManager(requireContext())
            binding.recyclerViewProofs.adapter = ProofVerificationResultAdapter(proofVerificationResults)

        } catch (e: Exception) {
            Log.e("SmartContractCompleted", "Error parsing results", e)
            // エラー時は空の状態を表示
            binding.textViewSuccessfulCount.text = "Error parsing results"
            binding.textViewFailedCount.text = ""
            binding.textViewTotalCount.text = ""
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
