package org.ethtokyo.hackathon.anastasia.data

import android.content.Context
import android.content.SharedPreferences

class SettingsRepository(private val context: Context) {

    private val sharedPreferences: SharedPreferences by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    companion object {
        private const val PREFS_NAME = "anastasia_settings"
        private const val KEY_SEPOLIA_API_KEY = "sepolia_api_key"
        private const val KEY_CA_CERT_VERIFIER_ADDRESS = "ca_cert_verifier_address"
        private const val KEY_EE_CERT_VERIFIER_ADDRESS = "ee_cert_verifier_address"
        private const val KEY_EE_CERT_LONG_VERIFIER_ADDRESS = "ee_cert_long_verifier_address"
    }

    fun saveSepoliaApiKey(apiKey: String) {
        sharedPreferences.edit()
            .putString(KEY_SEPOLIA_API_KEY, apiKey)
            .apply()
    }

    fun getSepoliaApiKey(): String {
        return sharedPreferences.getString(KEY_SEPOLIA_API_KEY, "") ?: ""
    }

    fun saveCaCertVerifierAddress(address: String) {
        sharedPreferences.edit()
            .putString(KEY_CA_CERT_VERIFIER_ADDRESS, address)
            .apply()
    }

    fun getCaCertVerifierAddress(): String {
        return sharedPreferences.getString(KEY_CA_CERT_VERIFIER_ADDRESS, "") ?: ""
    }

    fun saveEeCertVerifierAddress(address: String) {
        sharedPreferences.edit()
            .putString(KEY_EE_CERT_VERIFIER_ADDRESS, address)
            .apply()
    }

    fun getEeCertVerifierAddress(): String {
        return sharedPreferences.getString(KEY_EE_CERT_VERIFIER_ADDRESS, "") ?: ""
    }

    fun saveEeCertLongVerifierAddress(address: String) {
        sharedPreferences.edit()
            .putString(KEY_EE_CERT_LONG_VERIFIER_ADDRESS, address)
            .apply()
    }

    fun getEeCertLongVerifierAddress(): String {
        return sharedPreferences.getString(KEY_EE_CERT_LONG_VERIFIER_ADDRESS, "") ?: ""
    }
}