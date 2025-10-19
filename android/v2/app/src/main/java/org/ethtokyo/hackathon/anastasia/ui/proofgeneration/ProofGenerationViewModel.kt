package org.ethtokyo.hackathon.anastasia.ui.proofgeneration

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.ethtokyo.hackathon.anastasia.Constants
import org.ethtokyo.hackathon.anastasia.core.ECKeystoreHelper
import org.ethtokyo.hackathon.anastasia.core.selectAppropriateCircuit
import org.ethtokyo.hackathon.anastasia.data.AppSettings
import org.ethtokyo.hackathon.anastasia.data.ProofGenerationResult
import org.ethtokyo.hackathon.anastasia.data.ProofGenerationTime
import uniffi.mopro.CircuitMeta
import uniffi.mopro.proveChainJwt

class ProofGenerationViewModel(private val application: Application) : AndroidViewModel(application) {

    private val keystoreHelper = ECKeystoreHelper()

    private val appSettings = AppSettings.getInstance(application)

    private val _proofGenerationResult = MutableLiveData<Result<ProofGenerationResult>>()
    val proofGenerationResult: LiveData<Result<ProofGenerationResult>> = _proofGenerationResult

    private val _isLoading = MutableLiveData<Boolean>()
    val isLoading: LiveData<Boolean> = _isLoading

    private val _progressMessage = MutableLiveData<String>()
    val progressMessage: LiveData<String> = _progressMessage

    fun generateProof(proofAudience: String) {
        viewModelScope.launch {
            _isLoading.value = true
            _progressMessage.value = "Proof generation started..."

            try {
                delay(2000)
                val result = generateProofCore(proofAudience)

                _progressMessage.value = "Proof generation completed!"
                _proofGenerationResult.value = Result.success(result)

            } catch (e: Exception) {
                e.printStackTrace()
                _progressMessage.value = "Proof generation failed: ${e.message}"
                _proofGenerationResult.value = Result.failure(e)
                _isLoading.value = false
            }
        }
    }

    fun onNavigationCompleted() {
        _isLoading.value = false
    }

    fun resetState() {
        _isLoading.value = false
        _progressMessage.value = ""
    }

    private suspend fun generateProofCore(proofAudience: String): ProofGenerationResult = withContext(Dispatchers.IO) {
        val chain = keystoreHelper.getAttestationCertificate(Constants.KEY_ALIAS)

        // 証明書チェーンから子証明書（1番目）と親証明書（2番目）を取得
        require(chain != null && chain.size > 2) { "Attestation chain must contain at least 3 certificates" }

        // 実際のチェーンを短縮し、3枚目を擬似的にrootとして取り扱っている。
        // 将来的にはチェーンに含まれる全ての証明書を対象に証明を生成するはず。
        val endEntityCert = chain[0]
        val subRoot = chain[1]
        val rootCert = chain[2]

        val subrootCircuit = selectAppropriateCircuit(application.applicationContext, subRoot)
        val leafCircuit = selectAppropriateCircuit(application.applicationContext, endEntityCert)

        val proofStartTime = System.currentTimeMillis()
        val jwt = proveChainJwt(
            subrootCircuit,
            listOf<CircuitMeta>(),
            leafCircuit,
            rootCert.encoded,
            subRoot.encoded,
            listOf<ByteArray>(),
            endEntityCert.encoded,
            null,
            appSettings.getUserSk(),
            proofAudience,
            false
        )
        val proofEndTime = System.currentTimeMillis()

        return@withContext ProofGenerationResult(
            keyAttestationJwt = jwt,
            performance = ProofGenerationTime(
                proofStartTime,
                proofEndTime,
                proofEndTime - proofStartTime
            )
        )
    }
}