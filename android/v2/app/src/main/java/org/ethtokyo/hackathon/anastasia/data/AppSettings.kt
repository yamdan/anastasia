package org.ethtokyo.hackathon.anastasia.data

import android.content.Context
import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData

class AppSettings private constructor(context: Context) {

    private val repository = AppSettingsRepository(context.applicationContext)

    private val _sepoliaApiKey = MutableLiveData<String>()
    val sepoliaApiKey: LiveData<String> = _sepoliaApiKey

    private val _caCertVerifierAddress = MutableLiveData<String>()
    val caCertVerifierAddress: LiveData<String> = _caCertVerifierAddress

    private val _eeCertVerifierAddress = MutableLiveData<String>()
    val eeCertVerifierAddress: LiveData<String> = _eeCertVerifierAddress

    companion object {
        @Volatile
        private var INSTANCE: AppSettings? = null

        fun getInstance(context: Context): AppSettings {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: AppSettings(context).also { INSTANCE = it }
            }
        }
    }

    init {
        loadSettings()
    }

    fun loadSettings() {
        _sepoliaApiKey.value = repository.getSepoliaApiKey()
        _caCertVerifierAddress.value = repository.getCaCertVerifierAddress()
        _eeCertVerifierAddress.value = repository.getEeCertVerifierAddress()
    }

    fun updateSettings(
        sepoliaApiKey: String,
        caCertVerifierAddress: String,
        eeCertVerifierAddress: String,
    ) {
        repository.saveSepoliaApiKey(sepoliaApiKey)
        repository.saveCaCertVerifierAddress(caCertVerifierAddress)
        repository.saveEeCertVerifierAddress(eeCertVerifierAddress)

        // Update LiveData to notify all observers
        _sepoliaApiKey.value = sepoliaApiKey
        _caCertVerifierAddress.value = caCertVerifierAddress
        _eeCertVerifierAddress.value = eeCertVerifierAddress
    }

    // Synchronous getters for cases where LiveData observation is not suitable
    fun getSepoliaApiKeyValue(): String {
        val liveDataValue = _sepoliaApiKey.value
        val repositoryValue = repository.getSepoliaApiKey()
        val result = liveDataValue ?: repositoryValue
        Log.d("AppSettings", "getSepoliaApiKeyValue: liveData='$liveDataValue', repo='$repositoryValue', result='$result'")
        return result
    }

    fun getCaCertVerifierAddressValue(): String {
        val liveDataValue = _caCertVerifierAddress.value
        val repositoryValue = repository.getCaCertVerifierAddress()
        val result = liveDataValue ?: repositoryValue
        Log.d("AppSettings", "getCaCertVerifierAddressValue: liveData='$liveDataValue', repo='$repositoryValue', result='$result'")
        return result
    }

    fun getEeCertVerifierAddressValue(): String {
        val liveDataValue = _eeCertVerifierAddress.value
        val repositoryValue = repository.getEeCertVerifierAddress()
        val result = liveDataValue ?: repositoryValue
        Log.d("AppSettings", "getEeCertVerifierAddressValue: liveData='$liveDataValue', repo='$repositoryValue', result='$result'")
        return result
    }

}