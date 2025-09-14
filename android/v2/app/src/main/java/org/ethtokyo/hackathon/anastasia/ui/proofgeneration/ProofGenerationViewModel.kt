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
import org.ethtokyo.hackathon.anastasia.core.computeSubjectKeyId
import org.ethtokyo.hackathon.anastasia.core.extractECPublicKeyCoordinates
import uniffi.mopro.ProofResult
import uniffi.mopro.commitAttrs
import java.security.cert.X509Certificate

class ProofGenerationViewModel(private val application: Application) : AndroidViewModel(application) {

    private val keystoreHelper = ECKeystoreHelper()

    private val _proofGenerationResult = MutableLiveData<Result<Array<ProofResult>>>()
    val proofGenerationResult: LiveData<Result<Array<ProofResult>>> = _proofGenerationResult

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

    private fun bytesToHexString(bytes: ByteArray): String {
        return bytes.joinToString(" ") { String.format("%02x", it.toUByte().toInt()) }
    }

    private fun generateProofCore(): Array<ProofResult> {
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

        // prover.ktで定義されたグローバル定数を使用してproveParentChildRelを呼び出し
        val proofResult1 = proveParentChildRel(
            context = application.applicationContext,
            child = parentCert,
            parent = grandparentCert,
            caPrevCmt = caCommitResult.cmt,
            caPrevCmtR = caCommitResult.r
        )

        println("=== === === === proofResult1 : ${proofResult1.proof}")

        val proofResult2 = proveParentChildRel(
            context = application.applicationContext,
            child = childCert,
            parent = parentCert,
            caPrevCmt = proofResult1.nextCmt,
            caPrevCmtR = proofResult1.nextCmtR
        )

        println("=== === === === proofResult2 : ${proofResult2.proof}")

        return arrayOf(proofResult1, proofResult2)
    }
}