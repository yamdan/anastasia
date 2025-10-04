package org.ethtokyo.hackathon.anastasia.core


import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.cert.Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey


class ECKeystoreHelper {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_EC
        private const val EC_CURVE = "secp256r1" // P-256
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    fun generateKeyPair(alias: String, useStrongBox: Boolean, attestationChallenge: ByteArray? = null): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, ANDROID_KEYSTORE)

        val keyGenParameterSpecBuilder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec(EC_CURVE))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(
                attestationChallenge != null && attestationChallenge.size > 0 && useStrongBox
            )

        // 構成証明書を要求する場合はチャレンジを設定
        attestationChallenge?.let { challenge ->
            keyGenParameterSpecBuilder.setAttestationChallenge(challenge)
        }

        val keyGenParameterSpec = keyGenParameterSpecBuilder.build()

        keyPairGenerator.initialize(keyGenParameterSpec)
        return keyPairGenerator.generateKeyPair()
    }

    fun getOrCreteKeyPair(alias: String, useStrongBox: Boolean, attestationChallenge: ByteArray? = null): KeyPair? {
        if (keyExists(alias)) {
            val publicKey = getPublicKey(alias)
            val privateKey = getPrivateKey(alias)
            return KeyPair(publicKey, privateKey)
        }
        return generateKeyPair(alias, useStrongBox, attestationChallenge)
    }

    fun getAttestationCertificate(alias: String): Array<Certificate>? {
        return try {
            keyStore.getCertificateChain(alias)
        } catch (e: Exception) {
            null
        }
    }

    fun deleteEntry(alias: String): Boolean {
        return try {
            keyStore.deleteEntry(alias)
            true
        } catch (e: Exception) {
            false
        }
    }

    fun keyExists(alias: String): Boolean {
        return try {
            keyStore.containsAlias(alias)
        } catch (e: Exception) {
            false
        }
    }

    fun getPrivateKey(alias: String): ECPrivateKey? {
        return keyStore.getEntry(alias, null)?.let { entry ->
            if (entry is KeyStore.PrivateKeyEntry) {
                try {
                    entry.privateKey as? ECPrivateKey
                } catch (e: Exception) {
                    e.printStackTrace()
                    null
                }
            } else null
        }
    }

    fun getPublicKey(alias: String): ECPublicKey? {
        return try {
            val certificate = keyStore.getCertificate(alias)
            certificate?.publicKey as? ECPublicKey
        } catch (e: Exception) {
            null
        }
    }

    fun sign(signatureAlgorithm: String, alias: String, data: ByteArray): ByteArray {
        val private = getPrivateKey(alias)
        return Signature.getInstance(signatureAlgorithm).run {
            initSign(private)
            update(data)
            sign()
        }
    }
}