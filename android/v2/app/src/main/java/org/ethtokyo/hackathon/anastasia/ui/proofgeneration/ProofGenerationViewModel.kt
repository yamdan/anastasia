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
import org.ethtokyo.hackathon.anastasia.core.proveParentChildRel
import org.ethtokyo.hackathon.anastasia.core.computeSubjectKeyId
import org.ethtokyo.hackathon.anastasia.core.extractECPublicKeyCoordinates
import org.ethtokyo.hackathon.anastasia.data.ProofGenerationTime
import org.ethtokyo.hackathon.anastasia.data.ProofResult
import org.ethtokyo.hackathon.anastasia.data.ProofsGenerationResult
import uniffi.mopro.commitAttrs
import java.security.cert.X509Certificate

class ProofGenerationViewModel(private val application: Application) : AndroidViewModel(application) {

    private val keystoreHelper = ECKeystoreHelper()

    private val _proofsGenerationResult = MutableLiveData<Result<ProofsGenerationResult>>()
    val proofsGenerationResult: LiveData<Result<ProofsGenerationResult>> = _proofsGenerationResult

    private val _isLoading = MutableLiveData<Boolean>()
    val isLoading: LiveData<Boolean> = _isLoading

    private val _progressMessage = MutableLiveData<String>()
    val progressMessage: LiveData<String> = _progressMessage

    fun generateProof() {
        viewModelScope.launch {
            _isLoading.value = true
            _progressMessage.value = "Proof generation started..."

            try {
                delay(2000)
                val result = generateProofCore()

                _progressMessage.value = "Proof generation completed!"
                _proofsGenerationResult.value = Result.success(result)

            } catch (e: Exception) {
                e.printStackTrace()
                _progressMessage.value = "Proof generation failed: ${e.message}"
                _proofsGenerationResult.value = Result.failure(e)
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

    private fun bytesToHexString(bytes: ByteArray): String {
        return bytes.joinToString(" ") { String.format("%02x", it.toUByte().toInt()) }
    }

    private suspend fun generateProofCore(): ProofsGenerationResult = withContext(Dispatchers.IO) {
        val chain = keystoreHelper.getAttestationCertificate(Constants.KEY_ALIAS)

        // 証明書チェーンから子証明書（1番目）と親証明書（2番目）を取得
        require(chain != null && chain.size > 2) { "Attestation chain must contain at least 3 certificates" }

        val childCert = chain[0]
        val parentCert = chain[1]
        val grandparentCert = chain[2]

        // grandparent証明書から必要な情報を取得
        val grandparentX509 = grandparentCert as X509Certificate
        val grandParentSubject = grandparentX509.subjectX500Principal.encoded  // SubjectをDERエンコードバイト列で取得
        val caSubjectKeyIdentifier = computeSubjectKeyId(grandparentX509)  // Subject Key Identifierを取得
        val (subjectPkX, subjectPkY) = extractECPublicKeyCoordinates(grandparentX509)  // 公開鍵のx,y座標を取得

        println(bytesToHexString(grandParentSubject))

        val caCommitResult = commitAttrs(
            grandParentSubject,
            caSubjectKeyIdentifier,
            subjectPkX,
            subjectPkY,
            null
        )

        val individualTimes = mutableListOf<ProofGenerationTime>()

        // 第1の証明生成
        val proof1StartTime = System.currentTimeMillis()
        val proofResult1 = proveParentChildRel(
            context = application.applicationContext,
            child = parentCert,
            parent = grandparentCert,
            caPrevCmtX = caCommitResult.cmtX,
            caPrevCmtY = caCommitResult.cmtY,
            caPrevCmtR = caCommitResult.r
        )
        val proof1EndTime = System.currentTimeMillis()

        individualTimes.add(ProofGenerationTime(
            proofIndex = 1,
            startTime = proof1StartTime,
            endTime = proof1EndTime,
            durationMs = proof1EndTime - proof1StartTime
        ))

        // UIスレッドでプログレスメッセージを更新
        withContext(Dispatchers.Main) {
            _progressMessage.value = "Proof 1 of 2 completed (${(proof1EndTime - proof1StartTime) / 1000.0}s)"
        }

        // 第2の証明生成
        val proof2StartTime = System.currentTimeMillis()
        val proofResult2 = proveParentChildRel(
            context = application.applicationContext,
            child = childCert,
            parent = parentCert,
            caPrevCmtX = proofResult1.nextCmtX,
            caPrevCmtY = proofResult1.nextCmtY,
            caPrevCmtR = proofResult1.nextCmtR
        )
        val proof2EndTime = System.currentTimeMillis()

        individualTimes.add(ProofGenerationTime(
            proofIndex = 2,
            startTime = proof2StartTime,
            endTime = proof2EndTime,
            durationMs = proof2EndTime - proof2StartTime
        ))

        // UIスレッドでプログレスメッセージを更新
        withContext(Dispatchers.Main) {
            _progressMessage.value = "Proof 2 of 2 completed (${(proof2EndTime - proof2StartTime) / 1000.0}s)"
        }

        return@withContext ProofsGenerationResult(
            proofs = arrayOf(proofResult1, proofResult2),
            performances = individualTimes.toTypedArray()
        )
    }
}