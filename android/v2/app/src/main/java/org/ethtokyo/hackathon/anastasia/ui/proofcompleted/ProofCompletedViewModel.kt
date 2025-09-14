package org.ethtokyo.hackathon.anastasia.ui.proofcompleted

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.ethtokyo.hackathon.anastasia.Constants
import org.ethtokyo.hackathon.anastasia.core.convertProofForInfura
import org.ethtokyo.hackathon.anastasia.smart_contract.create_eth_call_json
import org.ethtokyo.hackathon.anastasia.smart_contract.resolveInfuraPath
import uniffi.mopro.ProofResult
import org.json.JSONArray
import org.json.JSONObject

data class ProofSubmissionResult(
    val proofIndex: Int,
    val isSuccess: Boolean,
    val response: String?,
    val error: String?
)

data class AllProofsResult(
    val results: List<ProofSubmissionResult>,
    val overallSuccess: Boolean
) {
    fun toJsonString(): String {
        val json = JSONObject()
        json.put("overallSuccess", overallSuccess)

        val resultsArray = JSONArray()
        results.forEach { result ->
            val resultJson = JSONObject()
            resultJson.put("proofIndex", result.proofIndex)
            resultJson.put("isSuccess", result.isSuccess)
            resultJson.put("response", result.response)
            resultJson.put("error", result.error)
            resultsArray.put(resultJson)
        }
        json.put("results", resultsArray)

        return json.toString()
    }
}

class ProofCompletedViewModel : ViewModel() {

    private val _postResult = MutableLiveData<Result<AllProofsResult>>()
    val postResult: LiveData<Result<AllProofsResult>> = _postResult

    private val _isLoading = MutableLiveData<Boolean>()
    val isLoading: LiveData<Boolean> = _isLoading

    private val client = OkHttpClient()

    fun recordProofs(proofs: Array<ProofResult>) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                val allResults = postProofToServer(proofs)
                _postResult.value = Result.success(allResults)
            } catch (e: Exception) {
                // 予期しないエラーの場合のみfailureとして扱う
                _postResult.value = Result.failure(e)
            } finally {
                _isLoading.value = false
            }
        }
    }

    private suspend fun postProofToServer(proofs: Array<ProofResult>): AllProofsResult = withContext(Dispatchers.IO) {
        val results = mutableListOf<ProofSubmissionResult>()
        val endpoint = resolveInfuraPath()

        proofs.forEachIndexed { index, proofResult ->
            try {
                val smContractAddress = if (proofResult.proof.startsWith("ca")){
                    Constants.SMART_CONTRACT_ADDRESS_CA
                } else {
                    Constants.SMART_CONTRACT_ADDRESS_EE
                }
                val converted = proofResult.convertProofForInfura()
                val jsonPayload = create_eth_call_json(smContractAddress, converted)
                val requestBody = jsonPayload.toRequestBody("application/json; charset=utf-8".toMediaType())
                val request = Request.Builder()
                    .url(endpoint)
                    .post(requestBody)
                    .build()

                client.newCall(request).execute().use { response ->
                    val responseBody = response.body?.string() ?: ""

                    if (response.isSuccessful) {
                        // 2XX系レスポンスの場合、さらにJSON内のerrorキーをチェック
                        val (isReallySuccess, errorMessage) = checkResponseForError(responseBody)

                        if (isReallySuccess) {
                            results.add(ProofSubmissionResult(
                                proofIndex = index,
                                isSuccess = true,
                                response = responseBody,
                                error = null
                            ))
                        } else {
                            results.add(ProofSubmissionResult(
                                proofIndex = index,
                                isSuccess = false,
                                response = responseBody,
                                error = errorMessage ?: "Server returned error in response"
                            ))
                        }
                    } else {
                        results.add(ProofSubmissionResult(
                            proofIndex = index,
                            isSuccess = false,
                            response = responseBody,
                            error = "HTTP ${response.code}: ${response.message}"
                        ))
                    }
                }
            } catch (e: Exception) {
                results.add(ProofSubmissionResult(
                    proofIndex = index,
                    isSuccess = false,
                    response = null,
                    error = e.message ?: "Unknown error"
                ))
            }
        }

        val overallSuccess = results.all { it.isSuccess }
        return@withContext AllProofsResult(results, overallSuccess)
    }

    /**
     * JSONレスポンス内の error キーをチェックして真の成功かどうかを判定
     * @param responseBody サーバーからのレスポンスボディ
     * @return Pair<成功かどうか, エラーメッセージ>
     */
    private fun checkResponseForError(responseBody: String): Pair<Boolean, String?> {
        return try {
            if (responseBody.isBlank()) {
                return Pair(false, "Empty response from server")
            }

            val json = JSONObject(responseBody)

            // "error" キーが存在する場合はエラーとして扱う
            if (json.has("error")) {
                val errorValue = json.get("error")
                val errorMessage = when (errorValue) {
                    is String -> errorValue
                    is JSONObject -> errorValue.toString()
                    else -> "Server returned error: $errorValue"
                }
                return Pair(false, errorMessage)
            }

            // "error" キーが存在しない場合は成功
            Pair(true, null)

        } catch (e: Exception) {
            // JSONパースに失敗した場合は、レスポンスが不正な形式として扱う
            Pair(false, "Invalid JSON response: ${e.message}")
        }
    }
}
