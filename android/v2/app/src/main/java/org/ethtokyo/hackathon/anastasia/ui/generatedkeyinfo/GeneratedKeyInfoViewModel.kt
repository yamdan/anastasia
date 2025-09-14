package org.ethtokyo.hackathon.anastasia.ui.generatedkeyinfo

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import org.ethtokyo.hackathon.anastasia.Constants
import org.ethtokyo.hackathon.anastasia.core.ECKeystoreHelper
import java.security.cert.Certificate

class GeneratedKeyInfoViewModel : ViewModel() {

    private val keystoreHelper = ECKeystoreHelper()

    private val _certificates = MutableLiveData<Array<Certificate>>()
    val certificates: LiveData<Array<Certificate>> = _certificates

    init {
        loadGeneratedCertificates()
    }

    private fun loadGeneratedCertificates() {
        try {
            val certificateChain = keystoreHelper.getAttestationCertificate(Constants.KEY_ALIAS)
            if (certificateChain != null) {
                _certificates.value = certificateChain
            } else {
                _certificates.value = emptyArray()
            }
        } catch (e: Exception) {
            _certificates.value = emptyArray()
        }
    }
}