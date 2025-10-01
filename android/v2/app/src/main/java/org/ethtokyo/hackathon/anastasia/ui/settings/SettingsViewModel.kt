package org.ethtokyo.hackathon.anastasia.ui.settings

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import org.ethtokyo.hackathon.anastasia.data.SettingsRepository

class SettingsViewModel(application: Application) : AndroidViewModel(application) {

    private val settingsRepository = SettingsRepository(application)

    private val _sepoliaApiKey = MutableLiveData<String>()
    val sepoliaApiKey: LiveData<String> = _sepoliaApiKey

    private val _caCertVerifierAddress = MutableLiveData<String>()
    val caCertVerifierAddress: LiveData<String> = _caCertVerifierAddress

    private val _eeCertVerifierAddress = MutableLiveData<String>()
    val eeCertVerifierAddress: LiveData<String> = _eeCertVerifierAddress

    private val _eeCertLongVerifierAddress = MutableLiveData<String>()
    val eeCertLongVerifierAddress: LiveData<String> = _eeCertLongVerifierAddress

    fun loadSettings() {
        _sepoliaApiKey.value = settingsRepository.getSepoliaApiKey()
        _caCertVerifierAddress.value = settingsRepository.getCaCertVerifierAddress()
        _eeCertVerifierAddress.value = settingsRepository.getEeCertVerifierAddress()
        _eeCertLongVerifierAddress.value = settingsRepository.getEeCertLongVerifierAddress()
    }

    fun saveSettings(
        sepoliaApiKey: String,
        caCertVerifierAddress: String,
        eeCertVerifierAddress: String,
        eeCertLongVerifierAddress: String
    ) {
        settingsRepository.saveSepoliaApiKey(sepoliaApiKey)
        settingsRepository.saveCaCertVerifierAddress(caCertVerifierAddress)
        settingsRepository.saveEeCertVerifierAddress(eeCertVerifierAddress)
        settingsRepository.saveEeCertLongVerifierAddress(eeCertLongVerifierAddress)

        // Update LiveData
        _sepoliaApiKey.value = sepoliaApiKey
        _caCertVerifierAddress.value = caCertVerifierAddress
        _eeCertVerifierAddress.value = eeCertVerifierAddress
        _eeCertLongVerifierAddress.value = eeCertLongVerifierAddress
    }
}