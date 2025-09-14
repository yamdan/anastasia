package org.ethtokyo.hackathon.anastasia.ui.home

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import org.ethtokyo.hackathon.anastasia.Constants
import org.ethtokyo.hackathon.anastasia.core.ECKeystoreHelper
import org.ethtokyo.hackathon.anastasia.data.CertificateInfo
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.Base64

class HomeViewModel : ViewModel() {

    private val keystoreHelper = ECKeystoreHelper()

    private val _certificates = MutableLiveData<List<CertificateInfo>>()
    val certificates: LiveData<List<CertificateInfo>> = _certificates

    init {
        loadCertificates()
    }

    private fun loadCertificates() {
        try {
            _certificates.value = loadAttestationCertificates()
        } catch (e: Exception) {
            _certificates.value = emptyList()
        }
    }

    private fun loadAttestationCertificates(): List<CertificateInfo> {
        if (keystoreHelper.keyExists(Constants.KEY_ALIAS)){
            val certificates = keystoreHelper.getAttestationCertificate(Constants.KEY_ALIAS)
            if (certificates != null) {
                println("=== === === loaded certificate size : ${certificates.size}")
                return certificates.map { cert ->
                    val x509 = cert as? X509Certificate
                    CertificateInfo(
                        certificate = cert,
                        subject = x509?.subjectX500Principal?.name ?: "",
                        issuer = x509?.issuerX500Principal?.name ?: "",
                        keyAlias = Constants.KEY_ALIAS,
                        // 末端証明書かどうかの判定: 中間証明書を持たない or BasicConstraints=-1
                        isEndEntity = x509?.basicConstraints == -1
                    )
                }
            }
        }
        return emptyList()
    }

    fun refreshCertificates() {
        loadCertificates()
    }

    fun hasGeneratedKey(): Boolean {
        return keystoreHelper.keyExists(Constants.KEY_ALIAS)
    }

    fun deleteKey(): Boolean {
        val result = keystoreHelper.deleteEntry(Constants.KEY_ALIAS)
        if (result) {
            // Refresh certificates after successful deletion
            loadCertificates()
        }
        return result
    }

    fun getCertificateChainAsPem(): String? {
        if (!keystoreHelper.keyExists(Constants.KEY_ALIAS)) {
            return null
        }

        val certificates = keystoreHelper.getAttestationCertificate(Constants.KEY_ALIAS)
        return if (certificates != null && certificates.isNotEmpty()) {
            certificates.joinToString("\n") { cert ->
                convertCertificateToPem(cert)
            }
        } else {
            null
        }
    }

    private fun convertCertificateToPem(certificate: Certificate): String {
        val encoded = Base64.getEncoder().encode(certificate.encoded)
        val base64String = String(encoded)

        val pemBuilder = StringBuilder()
        pemBuilder.append("-----BEGIN CERTIFICATE-----\n")

        // 64文字ごとに改行を入れる
        for (i in base64String.indices step 64) {
            val end = minOf(i + 64, base64String.length)
            pemBuilder.append(base64String.substring(i, end)).append("\n")
        }

        pemBuilder.append("-----END CERTIFICATE-----")
        return pemBuilder.toString()
    }

    private fun parseCertificateSubject(cert: X509Certificate): String {
        return cert.subjectDN.name.split(",").firstOrNull()?.trim() ?: "Unknown Subject"
    }

    private fun parseCertificateIssuer(cert: X509Certificate): String {
        return cert.issuerDN.name.split(",").firstOrNull()?.trim() ?: "Unknown Issuer"
    }
}