package org.ethtokyo.hackathon.anastasia.core

import uniffi.mopro.ProofResult
import uniffi.mopro.prove
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import android.content.Context
import uniffi.mopro.CircuitMeta
import java.math.BigInteger
import java.security.MessageDigest
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x509.Extension

fun bytes(vararg ints: Int): ByteArray =
    ints.map { it.toByte() }.toByteArray()

fun ProofResult.convertProofForInfura(): String {
    val originalProof = this.proof

    return originalProof
}

private fun bytesToHexString(bytes: ByteArray): String {
    return bytes.joinToString(" ") { String.format("%02x", it.toUByte().toInt()) }
}

fun proveParentChildRel(context: Context, child: Certificate, parent: Certificate, caPrevCmt: String, caPrevCmtR: String): ProofResult {
    val circuitForChild = selectAppropriateCircuit(context, child)
    val circuitMetaForLibrary = CircuitMeta(
        "${circuitForChild.circuit}-${circuitForChild.vk}-${circuitForChild.srs}",
        circuitForChild.circuit,
        circuitForChild.vk,
        circuitForChild.srs,
    )
    println("=== === === circuit : ${circuitForChild.circuit}")
    println("=== === === vk : ${circuitForChild.vk}")
    println("=== === === srs : ${circuitForChild.srs}")

    val parentX509 = parent as X509Certificate
    val childX509 = child as X509Certificate
    val certDerBytes = childX509.encoded

    // child証明書からAuthority Key Identifierを取得、なければparentのSubjectから算出
    val authorityKeyId = extractOrComputeAuthorityKeyId(childX509, parentX509)
    println("authorityKeyId: ${bytesToHexString(authorityKeyId)}")

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
    val extBytes = child.getExtensionValue(Extension.authorityKeyIdentifier.id)
    if (extBytes != null) {
        try {
            // 拡張があって keyIdentifier が取れればそれを返す
            parseAuthorityKeyId(extBytes)?.let { return it }
            // keyIdentifier が null（issuer+serial のみ等）の場合はフォールバックする
        } catch (e: Exception) {
            // 解析失敗時はログを出してフォールバック（壊れた拡張等を許容）
            // Log.w("CertUtil", "Failed to parse AKI, fallback to parent", e)
        }
    }
    // AKI 拡張が無い、あるいは keyIdentifier が取れなかった場合は parent から算出
    return computeSubjectKeyId(parent)
}


private fun parseAuthorityKeyId(extensionValue: ByteArray): ByteArray? {
    // getExtensionValue の出力は DER の OCTET STRING でラップされているため、確実にデコードする
    val outer = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(extensionValue))
    val akiAsn1 = AuthorityKeyIdentifier.getInstance(ASN1Primitive.fromByteArray(outer.octets))
    // keyIdentifier があればそれを返す（無ければ null を返す）
    return akiAsn1.keyIdentifier
}



fun computeSubjectKeyId(cert: X509Certificate): ByteArray {
    val ext = cert.getExtensionValue(Extension.subjectKeyIdentifier.id)
    return if (ext != null) {
        parseSubjectKeyId(ext)
    } else {
        computeSubjectKeyIdFromPublicKey(cert)
    }
}

private fun parseSubjectKeyId(extensionValue: ByteArray): ByteArray {
    val outer = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(extensionValue))
    val ski = SubjectKeyIdentifier.getInstance(ASN1Primitive.fromByteArray(outer.octets))
    return ski.keyIdentifier
        ?: throw IllegalArgumentException("Subject Key IdentifierのkeyIdentifierが存在しません")
}

private fun computeSubjectKeyIdFromPublicKey(cert: X509Certificate): ByteArray {
    val spki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(cert.publicKey.encoded))
    // publicKeyData の中身（BIT STRINGの中の生の公開鍵ビット列）を取り出して SHA-1
    val keyBytes = spki.publicKeyData.bytes
    return MessageDigest.getInstance("SHA-1").digest(keyBytes)
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