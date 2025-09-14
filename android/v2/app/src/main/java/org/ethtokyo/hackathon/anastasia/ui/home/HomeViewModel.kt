package org.ethtokyo.hackathon.anastasia.ui.home

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
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
            // TODO: 実装 - 実際のKeyStoreから証明書チェーンを取得
            // 現在はモック実装
            val mockCertificates = loadMockCertificates()
            _certificates.value = mockCertificates
        } catch (e: Exception) {
            _certificates.value = emptyList()
        }
    }

    private fun loadMockCertificates(): List<CertificateInfo> {
        // TODO: Replace with actual implementation
        // For now return empty list to show the FAB
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