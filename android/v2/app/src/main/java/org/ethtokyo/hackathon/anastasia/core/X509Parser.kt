package org.ethtokyo.hackathon.anastasia.core


import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PublicKey
import java.security.Security

data class X509ParseResult(
    val issuer: String,
    val subject: String,
    val signature: ByteArray,
    val publicKey: PublicKeyInfo,
    val signatureAlgorithm: String
)

data class PublicKeyInfo(
    val algorithm: String,
    val encoded: ByteArray
)

class X509Parser {

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    fun parse(certificateBytes: ByteArray): X509ParseResult {
        try {
            // BouncyCastleを使用してX.509証明書をパース
            val certHolder = X509CertificateHolder(certificateBytes)

            // Java標準のX509Certificateオブジェクトに変換
            val converter = JcaX509CertificateConverter().setProvider("BC")
            val x509Cert = converter.getCertificate(certHolder)

            // Issuerの取得（DN形式の文字列として）
            val issuer = certHolder.issuer.toString()

            // Subjectの取得（DN形式の文字列として）
            val subject = certHolder.subject.toString()

            // 署名値の取得
            val signature = certHolder.signature

            // 署名アルゴリズムの取得
            val signatureAlgorithm = certHolder.signatureAlgorithm.algorithm.id

            // 公開鍵の取得
            val publicKey = x509Cert.publicKey
            val publicKeyInfo = PublicKeyInfo(
                algorithm = publicKey.algorithm,
                encoded = publicKey.encoded
            )

            return X509ParseResult(
                issuer = issuer,
                subject = subject,
                signature = signature,
                publicKey = publicKeyInfo,
                signatureAlgorithm = signatureAlgorithm
            )

        } catch (e: Exception) {
            throw IllegalArgumentException("証明書のパースに失敗しました: ${e.message}", e)
        }
    }
}