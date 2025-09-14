package org.ethtokyo.hackathon.anastasia.ui.keygeneration

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.launch
import org.ethtokyo.hackathon.anastasia.core.ECKeystoreHelper
import java.security.KeyPair
import java.util.*

class KeyGenerationViewModel : ViewModel() {

    private val keystoreHelper = ECKeystoreHelper()

    private val _keyGenerationResult = MutableLiveData<Result<KeyPair>>()
    val keyGenerationResult: LiveData<Result<KeyPair>> = _keyGenerationResult

    private val _isLoading = MutableLiveData<Boolean>()
    val isLoading: LiveData<Boolean> = _isLoading

    fun generateKey(challenge: String?) {
        viewModelScope.launch {
            _isLoading.value = true

            try {
                val challengeBytes = challenge?.toByteArray()
                val alias = "key_${System.currentTimeMillis()}_${UUID.randomUUID()}"

                // TODO: 実装詳細 - 実際のTEE/StrongBox鍵生成処理
                val keyPair = keystoreHelper.generateKeyPair(
                    alias = alias,
                    useStrongBox = true,
                    attestationChallenge = challengeBytes
                )

                _keyGenerationResult.value = Result.success(keyPair)

            } catch (e: Exception) {
                _keyGenerationResult.value = Result.failure(e)
            } finally {
                _isLoading.value = false
            }
        }
    }
}