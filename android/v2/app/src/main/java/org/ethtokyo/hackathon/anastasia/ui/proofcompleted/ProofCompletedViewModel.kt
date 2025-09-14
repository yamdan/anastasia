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

class ProofCompletedViewModel : ViewModel() {

    private val _postResult = MutableLiveData<Result<String>>()
    val postResult: LiveData<Result<String>> = _postResult

    private val _isLoading = MutableLiveData<Boolean>()
    val isLoading: LiveData<Boolean> = _isLoading

    private val client = OkHttpClient()

    fun recordProofs(proofs: Array<ProofResult>) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                val response = postProofToServer(proofs)
                _postResult.value = Result.success(response)
            } catch (e: Exception) {
                _postResult.value = Result.failure(e)
            } finally {
                _isLoading.value = false
            }
        }
    }

    private suspend fun postProofToServer(proofs: Array<ProofResult>): String = withContext(Dispatchers.IO) {
        val responses = mutableListOf<String>()
        val endpoint = resolveInfuraPath()

        for (proofResult in proofs) {
            val converted = proofResult.convertProofForInfura()
            val jsonPayload = create_eth_call_json(Constants.SMART_CONTRACT_ADDRESS_CA, converted)
            val requestBody = jsonPayload.toRequestBody("application/json; charset=utf-8".toMediaType())
            val request = Request.Builder()
                .url(endpoint)
                .post(requestBody)
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw RuntimeException("Unexpected code ${response.code} ${response.message}")
                }
                val responseBody = response.body?.string() ?: ""
                responses.add(responseBody)
            }
        }

        return@withContext responses.joinToString("\n")
    }
}
