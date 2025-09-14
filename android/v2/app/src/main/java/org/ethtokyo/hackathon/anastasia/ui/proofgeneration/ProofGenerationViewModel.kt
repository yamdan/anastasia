package org.ethtokyo.hackathon.anastasia.ui.proofgeneration

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.ethtokyo.hackathon.anastasia.Constants
import org.ethtokyo.hackathon.anastasia.core.ECKeystoreHelper
import org.ethtokyo.hackathon.anastasia.core.proveParentChildRel
import org.ethtokyo.hackathon.anastasia.core.caPrevCmt
import org.ethtokyo.hackathon.anastasia.core.caPrevCmtR

class ProofGenerationViewModel(private val application: Application) : AndroidViewModel(application) {

    private val keystoreHelper = ECKeystoreHelper()

    private val _proofGenerationResult = MutableLiveData<Result<Array<String>>>()
    val proofGenerationResult: LiveData<Result<Array<String>>> = _proofGenerationResult

    private val _isLoading = MutableLiveData<Boolean>()
    val isLoading: LiveData<Boolean> = _isLoading

    fun generateProof() {
        viewModelScope.launch {
            _isLoading.value = true

            try {
                delay(2000)
                // Generate mock proof
                val proofString = generateProofCore()
                println("=== === === === generated proof string : ${proofString}")
                _proofGenerationResult.value = Result.success(proofString)

            } catch (e: Exception) {
                e.printStackTrace()
                _proofGenerationResult.value = Result.failure(e)
            } finally {
                _isLoading.value = false
            }
        }
    }

    private fun generateProofCore(): Array<String> {
        val chain = keystoreHelper.getAttestationCertificate(Constants.KEY_ALIAS)

        // 証明書チェーンから子証明書（1番目）と親証明書（2番目）を取得
        require(chain != null && chain.size > 2) { "Attestation chain must contain at least 3 certificates" }

        val childCert = chain[1]
        val parentCert = chain[2]

        // prover.ktで定義されたグローバル定数を使用してproveParentChildRelを呼び出し
        val proofResult = proveParentChildRel(
            context = application.applicationContext,
            child = childCert,
            parent = parentCert,
            caPrevCmt = caPrevCmt,
            caPrevCmtR = caPrevCmtR
        )

        // ProofResultからproofを抽出して返却
        return arrayOf(proofResult.proof)
    }
}