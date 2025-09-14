package org.ethtokyo.hackathon.anastasia.core

import uniffi.mopro.ProofResult
import uniffi.mopro.prove
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import android.content.Context
import uniffi.mopro.CircuitMeta
import uniffi.mopro.commitAttrs
import java.math.BigInteger
import java.security.MessageDigest

fun bytes(vararg ints: Int): ByteArray =
    ints.map { it.toByte() }.toByteArray()

fun ProofResult.convertProofForInfura(): String {
    val originalProof = this.proof

    return originalProof
}

fun proveParentChildRel(context: Context, child: Certificate, parent: Certificate, caPrevCmt: String, caPrevCmtR: String): ProofResult {
    val circuitForChild = selectAppropriateCircuit(context, child)
    val circuitMetaForLibrary = CircuitMeta(
        "${circuitForChild.circuit}-${circuitForChild.vk}-${circuitForChild.srs}",
        circuitForChild.circuit,
        circuitForChild.vk,
        circuitForChild.srs,
    )

    val parentX509 = parent as X509Certificate
    val childX509 = child as X509Certificate
    val certDerBytes = childX509.encoded

    // child証明書からAuthority Key Identifierを取得、なければparentのSubjectから算出
    val authorityKeyId = extractOrComputeAuthorityKeyId(childX509, parentX509)

    // parent証明書から公開鍵のx、y座標を抽出
    val (pubKeyX, pubKeyY) = extractECPublicKeyCoordinates(parentX509)

    // prove関数を呼び出し
    return prove(
        circuitMetaForLibrary,
        certDerBytes,
        authorityKeyId,
        pubKeyX,
        pubKeyY,
        caPrevCmt,
        caPrevCmtR
    )
}

private fun extractOrComputeAuthorityKeyId(child: X509Certificate, parent: X509Certificate): ByteArray {
    // Authority Key Identifier拡張を取得
    val authorityKeyIdExtension = child.getExtensionValue("2.5.29.35")

    return if (authorityKeyIdExtension != null) {
        // 拡張が存在する場合、ASN.1構造をパースして実際の値を抽出
        parseAuthorityKeyId(authorityKeyIdExtension)
    } else {
        // 拡張が存在しない場合、parentのSubject Public Key InfoからSHA-1ハッシュを計算
        computeSubjectKeyId(parent)
    }
}

private fun parseAuthorityKeyId(extensionValue: ByteArray): ByteArray {
    // ASN.1 OCTET STRINGをスキップし、内部のAuthorityKeyIdをパース
    // 簡略化した実装：実際のASN.1パーサーを使用することを推奨
    var offset = 0
    // OCTET STRINGタグをスキップ
    if (extensionValue[offset] == 0x04.toByte()) {
        offset++
        val length = extensionValue[offset].toInt() and 0xFF
        offset++
        if (length > 127) {
            // 長い形式の長さ
            val lengthOfLength = length and 0x7F
            offset += lengthOfLength
        }
    }

    // AuthorityKeyIdのSEQUENCEをスキップ
    if (extensionValue[offset] == 0x30.toByte()) {
        offset += 2 // タグと長さをスキップ
    }

    // keyIdentifier [0] IMPLICIT KeyIdentifierを探す
    if (extensionValue[offset] == 0x80.toByte()) {
        offset++
        val keyIdLength = extensionValue[offset].toInt() and 0xFF
        offset++
        return extensionValue.sliceArray(offset until offset + keyIdLength)
    }

    throw IllegalArgumentException("Authority Key Identifierの解析に失敗しました")
}

fun computeSubjectKeyId(cert: X509Certificate): ByteArray {
    val subjectKeyIdExtension = cert.getExtensionValue("2.5.29.14")

    return if (subjectKeyIdExtension != null) {
        println("=== === === found subject key id")
        parseSubjectKeyId(subjectKeyIdExtension)
    } else {
        // 拡張が存在しない場合、Subject Public Key InfoからSHA-1ハッシュを計算
        computeSubjectKeyIdFromPublicKey(cert)
    }
}

private fun parseSubjectKeyId(extensionValue: ByteArray): ByteArray {
    // ASN.1 OCTET STRINGをスキップし、内部のSubjectKeyIdをパース
    var offset = 0
    // OCTET STRINGタグをスキップ
    if (extensionValue[offset] == 0x04.toByte()) {
        offset++
        val length = extensionValue[offset].toInt() and 0xFF
        offset++
        if (length > 127) {
            // 長い形式の長さ
            val lengthOfLength = length and 0x7F
            offset += lengthOfLength
        }
    }

    // Subject Key Identifierは通常もう一層のOCTET STRINGでラップされている
    if (extensionValue[offset] == 0x04.toByte()) {
        offset++
        val keyIdLength = extensionValue[offset].toInt() and 0xFF
        offset++
        return extensionValue.sliceArray(offset until offset + keyIdLength)
    }

    throw IllegalArgumentException("Subject Key Identifierの解析に失敗しました")
}

private fun computeSubjectKeyIdFromPublicKey(cert: X509Certificate): ByteArray {
    // RFC 5280に従ってSubject Key Identifierを算出
    val publicKeyInfo = cert.publicKey.encoded
    val digest = MessageDigest.getInstance("SHA-1")

    // Subject Public Key Info全体ではなく、公開鍵部分のみをハッシュ化
    // この実装は簡略化されており、実際にはBIT STRINGから公開鍵バイトを抽出する必要がある
    return digest.digest(publicKeyInfo).sliceArray(0..19) // 20バイト
}

fun extractECPublicKeyCoordinates(cert: X509Certificate): Pair<ByteArray, ByteArray> {
    val publicKey = cert.publicKey as ECPublicKey
    val ecPoint = publicKey.w

    // ECPointからx, y座標を取得
    val x = ecPoint.affineX
    val y = ecPoint.affineY

    // BigIntegerを32バイトのバイト配列に変換（先頭ゼロ埋め）
    val xBytes = bigIntegerToFixedSizeByteArray(x, 32)
    val yBytes = bigIntegerToFixedSizeByteArray(y, 32)

    return Pair(xBytes, yBytes)
}

private fun bigIntegerToFixedSizeByteArray(bigInt: BigInteger, size: Int): ByteArray {
    val bytes = bigInt.toByteArray()

    return when {
        bytes.size == size -> bytes
        bytes.size > size -> {
            // 先頭の0x00バイトを削除（符号ビット）
            if (bytes[0] == 0.toByte() && bytes.size == size + 1) {
                bytes.sliceArray(1 until bytes.size)
            } else {
                throw IllegalArgumentException("BigIntegerが指定サイズを超えています")
            }
        }
        else -> {
            // 先頭にゼロを埋める
            ByteArray(size - bytes.size) + bytes
        }
    }
}