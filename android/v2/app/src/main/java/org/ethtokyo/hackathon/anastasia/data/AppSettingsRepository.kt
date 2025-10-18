package org.ethtokyo.hackathon.anastasia.data

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import org.ethtokyo.hackathon.anastasia.BuildConfig

class AppSettingsRepository(private val context: Context) {

    private val sharedPreferences: SharedPreferences by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    companion object {
        private const val PREFS_NAME = "anastasia_settings"
        private const val KEY_SEPOLIA_API_KEY = "sepolia_api_key"
        private const val KEY_CA_CERT_VERIFIER_ADDRESS = "ca_cert_verifier_address"
        private const val KEY_EE_CERT_VERIFIER_ADDRESS = "ee_cert_verifier_address"
        private const val USER_SK = "user_sk"
    }
    private fun isValidHexString(value: String): Boolean {
        if (value.isBlank()) return false
        return value.matches(Regex("^[0-9a-fA-F]+$"))
    }

    fun saveSepoliaApiKey(apiKey: String) {
        sharedPreferences.edit()
            .putString(KEY_SEPOLIA_API_KEY, apiKey)
            .apply()
    }

    fun getSepoliaApiKey(): String {
        val stored = sharedPreferences.getString(KEY_SEPOLIA_API_KEY, null)
        val defaultValue = BuildConfig.SEPOLIA_API_KEY
        val result = if (stored.isNullOrBlank()) defaultValue ?: "" else stored
        Log.d("AppSettingsRepo", "getSepoliaApiKey: stored='$stored', default='$defaultValue', result='$result'")
        return if (isValidHexString(result)) {
            result
        } else {
            Log.d("AppSettings", "getSepoliaApiKeyValue: '$result' is not a valid hex string, returning empty string")
            ""
        }
    }

    fun saveCaCertVerifierAddress(address: String) {
        sharedPreferences.edit()
            .putString(KEY_CA_CERT_VERIFIER_ADDRESS, address)
            .apply()
    }

    fun getCaCertVerifierAddress(): String {
        val stored = sharedPreferences.getString(KEY_CA_CERT_VERIFIER_ADDRESS, null)
        val defaultValue = BuildConfig.SC_ADDRESS_CA
        val result = if (stored.isNullOrBlank()) defaultValue ?: "" else stored
        Log.d("AppSettingsRepo", "getCaCertVerifierAddress: stored='$stored', default='$defaultValue', result='$result'")
        return result
    }

    fun saveEeCertVerifierAddress(address: String) {
        sharedPreferences.edit()
            .putString(KEY_EE_CERT_VERIFIER_ADDRESS, address)
            .apply()
    }

    fun getEeCertVerifierAddress(): String {
        val stored = sharedPreferences.getString(KEY_EE_CERT_VERIFIER_ADDRESS, null)
        val defaultValue = BuildConfig.SC_ADDRESS_EE
        val result = if (stored.isNullOrBlank()) defaultValue ?: "" else stored
        Log.d("AppSettingsRepo", "getEeCertVerifierAddress: stored='$stored', default='$defaultValue', result='$result'")
        return result
    }

    fun saveUserSk(usersk: String) {
        sharedPreferences.edit()
            .putString(USER_SK, usersk)
            .apply()
    }

    fun getUserSk(): String {
        val stored = sharedPreferences.getString(USER_SK, null)
        val result = if (stored.isNullOrBlank()) "" else stored
        return result
    }
}