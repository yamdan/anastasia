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
import uniffi.mopro.proveChainComposedJwt
import uniffi.mopro.proveChainJwt
import java.security.cert.Certificate

class ProofGenerationViewModel(private val application: Application) : AndroidViewModel(application) {

    private val keystoreHelper = ECKeystoreHelper()

    private val appSettings = AppSettings.getInstance(application)

    private val _proofGenerationResult = MutableLiveData<Result<ProofGenerationResult>>()
    val proofGenerationResult: LiveData<Result<ProofGenerationResult>> = _proofGenerationResult

    private val _isLoading = MutableLiveData<Boolean>()
    val isLoading: LiveData<Boolean> = _isLoading

    private val _progressMessage = MutableLiveData<String>()
    val progressMessage: LiveData<String> = _progressMessage

    fun generateProof(proofAudience: String, circuitType: String) {
        viewModelScope.launch {
            _isLoading.value = true
            _progressMessage.value = "Key attestation JWT generation started..."

            try {
                delay(2000)
                val result = generateProofCore(proofAudience, circuitType)

                _progressMessage.value = "Key attestation JWT has been generated!"
                _proofGenerationResult.value = Result.success(result)

            } catch (e: Exception) {
                e.printStackTrace()
                _progressMessage.value = "Key attestation JWT generation failed: ${e.message}"
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

    private suspend fun generateProofCore(proofAudience: String, circuitType: String): ProofGenerationResult = withContext(Dispatchers.IO) {
        val chain = keystoreHelper.getAttestationCertificate(Constants.KEY_ALIAS)

        var jwt: String
        var proofStartTime: Long
        var proofEndTime: Long
        if (circuitType == "es384") {
            require(chain != null && chain.size > 3) { "Attestation chain must contain at least 4 certificates" }

            val rootCert = chain[3]
            val subRootCert = chain[2]
            val caCerts = listOf(chain[1])
            val leafCert = chain[0]

            // TODO: avoid hardcoded circuit IDs
            val subrootCircuit = selectAppropriateCircuit(application.applicationContext, "es384_subroot/0.2.0")
            val caCircuits = listOf(selectAppropriateCircuit(application.applicationContext, "es256_ca/0.2.0"))
            val leafCircuit = selectAppropriateCircuit(application.applicationContext, "es256_ee/0.2.0")

            proofStartTime = System.currentTimeMillis()
            jwt = proveChainJwt(
                subrootCircuit,
                caCircuits,
                leafCircuit,
                rootCert.encoded,
                subRootCert.encoded,
                caCerts.map { caCert -> caCert.encoded },
                leafCert.encoded,
                null,
                appSettings.getUserSk(),
                proofAudience,
                false
            )
            proofEndTime = System.currentTimeMillis()
        } else if (circuitType == "es256") {
            // 証明書チェーンから子証明書（1番目）と親証明書（2番目）を取得
            require(chain != null && chain.size > 2) { "Attestation chain must contain at least 3 certificates" }

            // 実際のチェーンを短縮し、3枚目を擬似的にrootとして取り扱っている。
            // 将来的にはチェーンに含まれる全ての証明書を対象に証明を生成するはず。
            val rootCert = chain[2]
            val subRootCert = chain[1]
            val leafCert = chain[0]

            // TODO: avoid hardcoded circuit IDs
            val subrootCircuit = selectAppropriateCircuit(application.applicationContext, "es256_subroot/0.3.0")
            val leafCircuit = selectAppropriateCircuit(application.applicationContext, "es256_ee/0.2.0")

            proofStartTime = System.currentTimeMillis()
            jwt = proveChainJwt(
                subrootCircuit,
                listOf(),
                leafCircuit,
                rootCert.encoded,
                subRootCert.encoded,
                listOf(),
                leafCert.encoded,
                null,
                appSettings.getUserSk(),
                proofAudience,
                false
            )
            proofEndTime = System.currentTimeMillis()
        } else if (circuitType == "es384-composed") {
            require(chain != null && chain.size > 3) { "Attestation chain must contain at least 4 certificates" }

            val rootCert = chain[3]
            val subRootCert = chain[2]
            val caCerts = listOf(chain[1])
            val leafCert = chain[0]

            // TODO: avoid hardcoded circuit IDs
            val circuit = selectAppropriateCircuit(application.applicationContext, "es384_composed/0.1.0")

            proofStartTime = System.currentTimeMillis()
            jwt = proveChainComposedJwt(
                circuit,
                rootCert.encoded,
                subRootCert.encoded,
                caCerts.map { caCert -> caCert.encoded },
                leafCert.encoded,
                null,
                appSettings.getUserSk(),
                proofAudience,
                false
            )
            proofEndTime = System.currentTimeMillis()
        } else {
            throw Error()
        }

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