package org.ethtokyo.hackathon.anastasia.ui.home

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import org.ethtokyo.hackathon.anastasia.Constants
import org.ethtokyo.hackathon.anastasia.core.ECKeystoreHelper
import org.ethtokyo.hackathon.anastasia.data.CertificateInfo
import java.security.cert.X509Certificate

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

    private fun parseCertificateSubject(cert: X509Certificate): String {
        return cert.subjectDN.name.split(",").firstOrNull()?.trim() ?: "Unknown Subject"
    }

    private fun parseCertificateIssuer(cert: X509Certificate): String {
        return cert.issuerDN.name.split(",").firstOrNull()?.trim() ?: "Unknown Issuer"
    }
}