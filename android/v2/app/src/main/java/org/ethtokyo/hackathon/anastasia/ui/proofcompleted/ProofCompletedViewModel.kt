package org.ethtokyo.hackathon.anastasia.ui.proofcompleted

import android.app.Application
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.ethtokyo.hackathon.anastasia.Constants
import org.ethtokyo.hackathon.anastasia.core.smart_contract.convertProofForInfura
import org.ethtokyo.hackathon.anastasia.data.AppSettings
import org.ethtokyo.hackathon.anastasia.data.ProofResult
import org.ethtokyo.hackathon.anastasia.data.exceptions.InvalidDestinationException
import org.ethtokyo.hackathon.anastasia.core.smart_contract.create_eth_call_json
import org.ethtokyo.hackathon.anastasia.core.smart_contract.resolveInfuraPath
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

data class ProofSubmissionResult(
    val proofIndex: Int,
    val isSuccess: Boolean,
    val response: String?,
    val error: String?,
    val smartContractAddress: String
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
            resultJson.put("smartContractAddress", result.smartContractAddress)
            resultsArray.put(resultJson)
        }
        json.put("results", resultsArray)

        return json.toString()
    }
}

class ProofCompletedViewModel(application: Application) : AndroidViewModel(application) {

    private val appSettings = AppSettings.getInstance(application)

    private val _postResult = MutableLiveData<Result<AllProofsResult>>()
    val postResult: LiveData<Result<AllProofsResult>> = _postResult

    private val _isLoading = MutableLiveData<Boolean>()
    val isLoading: LiveData<Boolean> = _isLoading

    private val _progressMessage = MutableLiveData<String>()
    val progressMessage: LiveData<String> = _progressMessage

    private val client = OkHttpClient().newBuilder()
        .connectTimeout(Constants.SmartContract.CONNECT_TIMEOUT, TimeUnit.SECONDS)
        .writeTimeout(Constants.SmartContract.WRITE_TIMEOUT, TimeUnit.SECONDS)
        .readTimeout(Constants.SmartContract.READ_TIMEOUT, TimeUnit.SECONDS)
        .build()


    fun verifyProofs(proofs: Array<ProofResult>) {
        viewModelScope.launch {
            _isLoading.value = true
            _progressMessage.value = "Preparing proof submissions..."
            try {
                val allResults = postProofToServer(proofs)
                _postResult.value = Result.success(allResults)
            } catch (e: Exception) {
                // 予期しないエラーの場合のみfailureとして扱う
                _postResult.value = Result.failure(e)
            } finally {
                _isLoading.value = false
                _progressMessage.value = ""
            }
        }
    }

    private suspend fun postProofToServer(proofs: Array<ProofResult>): AllProofsResult = withContext(Dispatchers.IO) {
        val results = mutableListOf<ProofSubmissionResult>()
        val apiKey = appSettings.getSepoliaApiKeyValue()
        val endpoint = resolveInfuraPath(apiKey)

        proofs.forEachIndexed { index, proofResult ->
            // プログレス更新（UIスレッドで実行）
            withContext(Dispatchers.Main) {
                _progressMessage.value = "Submitting proof ${index + 1} of ${proofs.size}..."
            }

            try {
                val smContractAddress = if (proofResult.proofForEE){
                    val eeLongAddress = appSettings.getEeCertLongVerifierAddressValue()
                    Log.d("ProofCompletedVM", "EE Long Address from settings: '$eeLongAddress'")
                    if (eeLongAddress.isBlank()){
                        Log.e("ProofCompletedVM", "EE Cert Long Verifier Address is blank!")
                        throw InvalidDestinationException("EE Cert Long Verifier Address is blank. Check Settings page.")
                    }
                    eeLongAddress
                } else {
                    val caAddress = appSettings.getCaCertVerifierAddressValue()
                    Log.d("ProofCompletedVM", "CA Address from settings: '$caAddress'")
                    if (caAddress.isBlank()){
                        Log.e("ProofCompletedVM", "CA Cert Verifier Address is blank!")
                        throw InvalidDestinationException("CA Cert Verifier Address is blank. Check Settings page.")
                    }
                    caAddress
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
                                error = null,
                                smartContractAddress = smContractAddress
                            ))
                        } else {
                            results.add(ProofSubmissionResult(
                                proofIndex = index,
                                isSuccess = false,
                                response = responseBody,
                                error = errorMessage ?: "Server returned error in response",
                                smartContractAddress = smContractAddress
                            ))
                        }
                    } else {
                        results.add(ProofSubmissionResult(
                            proofIndex = index,
                            isSuccess = false,
                            response = responseBody,
                            error = "HTTP ${response.code}: ${response.message}",
                            smartContractAddress = smContractAddress
                        ))
                    }
                }
            } catch (e: Exception) {
                results.add(ProofSubmissionResult(
                    proofIndex = index,
                    isSuccess = false,
                    response = null,
                    error = e.message ?: "Unknown error",
                    smartContractAddress = ""
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
