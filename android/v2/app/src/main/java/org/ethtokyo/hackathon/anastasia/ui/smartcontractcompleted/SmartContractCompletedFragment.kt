package org.ethtokyo.hackathon.anastasia.ui.smartcontractcompleted

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import androidx.navigation.fragment.navArgs
import org.ethtokyo.hackathon.anastasia.R
import org.ethtokyo.hackathon.anastasia.databinding.FragmentSmartContractCompletedBinding
import org.json.JSONObject
import org.json.JSONArray

class SmartContractCompletedFragment : Fragment() {

    private var _binding: FragmentSmartContractCompletedBinding? = null
    private val binding get() = _binding!!
    private val args: SmartContractCompletedFragmentArgs by navArgs()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentSmartContractCompletedBinding.inflate(inflater, container, false)

        // JSONデータをユーザーフレンドリーな形式に変換して表示
        val formattedText = formatProofResults(args.responseData)
        binding.textViewResponseData.text = formattedText

        binding.buttonFinish.setOnClickListener {
            findNavController().navigate(R.id.action_smartContractCompletedFragment_to_navigation_key_management)
        }

        return binding.root
    }

    private fun formatProofResults(jsonData: String): String {
        return try {
            val json = JSONObject(jsonData)
            val overallSuccess = json.getBoolean("overallSuccess")
            val resultsArray = json.getJSONArray("results")

            val builder = StringBuilder()

            // 全体結果のサマリー
            builder.append("=== Proof Submission Results ===\n\n")
            builder.append("Total Proofs: ${resultsArray.length()}\n\n")

            // 各proofの詳細結果
            for (i in 0 until resultsArray.length()) {
                val result = resultsArray.getJSONObject(i)
                val proofIndex = result.getInt("proofIndex")
                val isSuccess = result.getBoolean("isSuccess")
                val response = result.optString("response", null)
                val error = result.optString("error", null)

                builder.append("--- Proof ${proofIndex + 1} ---\n")
                builder.append("Status: ${if (isSuccess) "✅ Success" else "❌ Failed"}\n")

                if (isSuccess && !response.isNullOrEmpty()) {
                    // レスポンスが成功の場合、簡潔に表示
                    builder.append("Response: ✅ Verification successful\n")
                    // レスポンスの概要を表示（JSONの場合は整理して表示）
                    val responsePreview = formatResponsePreview(response)
                    builder.append("Details: $responsePreview\n")
                } else if (!isSuccess) {
                    // エラーの場合、詳細な情報を表示
                    if (!error.isNullOrEmpty()) {
                        builder.append("Error: $error\n")
                    }

                    // エラー時でもレスポンスがある場合は表示（サーバーエラーの詳細など）
                    if (!response.isNullOrEmpty() && response != error) {
                        val responsePreview = formatResponsePreview(response)
                        builder.append("Server Response: $responsePreview\n")
                    }
                }

                if (i < resultsArray.length() - 1) {
                    builder.append("\n")
                }
            }

            // 成功・失敗の統計
            val successCount = (0 until resultsArray.length()).count { i ->
                resultsArray.getJSONObject(i).getBoolean("isSuccess")
            }
            val failureCount = resultsArray.length() - successCount

            builder.append("\n=== Summary ===\n")
            builder.append("✅ Successful: $successCount\n")
            builder.append("❌ Failed: $failureCount\n")

            builder.toString()

        } catch (e: Exception) {
            // JSONのパースに失敗した場合は、元のデータをそのまま表示
            "Error parsing results:\n\n$jsonData"
        }
    }

    /**
     * レスポンス内容を見やすい形式でプレビュー
     */
    private fun formatResponsePreview(response: String): String {
        return try {
            if (response.isBlank()) return "Empty response"

            // JSONとしてパースを試みる
            val json = JSONObject(response)

            // "result" キーがある場合は、その値を表示
            if (json.has("result")) {
                val result = json.get("result").toString()
                if (result.length > 100) {
                    "${result.take(100)}..."
                } else {
                    result
                }
            }
            // "id", "jsonrpc" などの標準的なキーがある場合はJSON-RPCレスポンス
            else if (json.has("id") || json.has("jsonrpc")) {
                "JSON-RPC Response: ${if (response.length > 80) response.take(80) + "..." else response}"
            }
            // その他のJSONの場合
            else {
                if (response.length > 100) {
                    "${response.take(100)}..."
                } else {
                    response
                }
            }

        } catch (e: Exception) {
            // JSONでない場合は、そのまま表示（長い場合は省略）
            if (response.length > 100) {
                "${response.take(100)}..."
            } else {
                response
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
