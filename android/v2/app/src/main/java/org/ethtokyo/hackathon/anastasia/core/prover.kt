package org.ethtokyo.hackathon.anastasia.core

import org.ethtokyo.hackathon.anastasia.data.ProofResult as InternalProofResult
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import android.content.Context
import uniffi.mopro.CircuitMeta

fun bytes(vararg ints: Int): ByteArray =
    ints.map { it.toByte() }.toByteArray()


/*
fun proveParentChildRel(context: Context, child: Certificate, parent: Certificate, caPrevCmtX: String,caPrevCmtY: String, caPrevCmtR: String): InternalProofResult {
    val circuitForChild = selectAppropriateCircuit(context, child)
    val circuitMetaForLibrary = CircuitMeta(
        "${circuitForChild.circuit}-${circuitForChild.vk}-${circuitForChild.srs}",
        circuitForChild.circuit,
        circuitForChild.vk,
        circuitForChild.keccak_vk,
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
    val moproProved = prove(
        circuitMetaForLibrary,
        certDerBytes,
        authorityKeyId,
        pubKeyX,
        pubKeyY,
        caPrevCmtX,
        caPrevCmtY,
        caPrevCmtR,
        null
    )

    return InternalProofResult(
        proofForEE = child.isEndEntity(),
        proof = moproProved.proof,
        publicInputs = moproProved.publicInputs,
        numPublicInputs = moproProved.numPublicInputs,
        nextCmtX = moproProved.nextCmtX,
        nextCmtY = moproProved.nextCmtY,
        nextCmtR = moproProved.nextCmtR
    )
}
*/