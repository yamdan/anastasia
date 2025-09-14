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
import org.ethtokyo.hackathon.anastasia.smart_contract.resolveInfuraPath

class ProofCompletedViewModel : ViewModel() {

    private val _postResult = MutableLiveData<Result<String>>()
    val postResult: LiveData<Result<String>> = _postResult

    private val _isLoading = MutableLiveData<Boolean>()
    val isLoading: LiveData<Boolean> = _isLoading

    private val client = OkHttpClient()

    fun recordProof(proof: String) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                val response = postProofToServer(proof)
                _postResult.value = Result.success(response)
            } catch (e: Exception) {
                _postResult.value = Result.failure(e)
            } finally {
                _isLoading.value = false
            }
        }
    }

    private suspend fun postProofToServer(proof: String): String = withContext(Dispatchers.IO) {
        val requestBody = proof.toRequestBody("application/json; charset=utf-8".toMediaType())
        val request = Request.Builder()
            .url(resolveInfuraPath())
            .post(requestBody)
            .build()

        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw RuntimeException("Unexpected code ${response.code} ${response.message}")
            }
            response.body?.string() ?: ""
        }
    }
}
