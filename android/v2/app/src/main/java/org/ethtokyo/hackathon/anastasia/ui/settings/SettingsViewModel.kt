package org.ethtokyo.hackathon.anastasia.ui.settings

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import org.ethtokyo.hackathon.anastasia.data.AppSettings

class SettingsViewModel(application: Application) : AndroidViewModel(application) {

    private val appSettings = AppSettings.getInstance(application)

    val sepoliaApiKey: LiveData<String> = appSettings.sepoliaApiKey
    val caCertVerifierAddress: LiveData<String> = appSettings.caCertVerifierAddress
    val eeCertVerifierAddress: LiveData<String> = appSettings.eeCertVerifierAddress
    val eeCertLongVerifierAddress: LiveData<String> = appSettings.eeCertLongVerifierAddress

    fun loadSettings() {
        appSettings.loadSettings()
    }

    fun saveSettings(
        sepoliaApiKey: String,
        caCertVerifierAddress: String,
        eeCertVerifierAddress: String,
        eeCertLongVerifierAddress: String
    ) {
        appSettings.updateSettings(
            sepoliaApiKey,
            caCertVerifierAddress,
            eeCertVerifierAddress,
            eeCertLongVerifierAddress
        )
    }
}