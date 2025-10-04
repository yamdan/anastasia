package org.ethtokyo.hackathon.anastasia.core.smart_contract

import org.ethtokyo.hackathon.anastasia.Constants
import org.ethtokyo.hackathon.anastasia.data.ProofResult

fun create_eth_call_json(to: String, data: String): String {
    return """
{
  "jsonrpc": "2.0",
  "method": "eth_call",
  "params": [
    {
      "to": "$to",
      "data": "$data"
    },
    "latest"
  ],
  "id": 1
}
""".trimIndent()
}


fun resolveInfuraPath(apiKey: String): String {
    return joinPathToInfura(apiKey)
}

fun joinPathToInfura(path: String): String {
    val baseUrl = Constants.SmartContract.INFURA_ENDPOINT_URL.removeSuffix("/")
    val pathSegment = path.removePrefix("/")
    return "$baseUrl/$pathSegment"
}

// 内部ProofResult型用の拡張関数
fun ProofResult.convertProofForInfura(): String {

    val publicInputsHex = this.publicInputs.joinToString(separator = "")
    val proofDataHex = this.proof
    val proofLength = proofDataHex.length / 2 // バイト数

    // --- ABI 構造を構築 ---
    val methodId = "ea50d0e4" // 固定 MethodID

    // proofOffset: arguments 領域(2ワード=64バイト)の後
    val proofOffset = "0000000000000000000000000000000000000000000000000000000000000040"

    // proof のパディング処理（32バイト境界）
    val remainder = proofDataHex.length % 64
    val proofDataPadded = if (remainder != 0) {
        proofDataHex + "0".repeat(64 - remainder)
    } else {
        proofDataHex
    }

    // publicInputsOffset = arguments領域(64) + proofLength(32) + proofData領域
    val proofDataPaddedLength = proofDataPadded.length / 2 // バイト数
    val publicInputsOffsetValue = 64 + 32 + proofDataPaddedLength
    val publicInputsOffset = publicInputsOffsetValue.toString(16).padStart(64, '0')

    // proof length (1ワード)
    val proofLengthPadded = proofLength.toString(16).padStart(64, '0')

    val publicInputsCount = this.numPublicInputs.toString(16).padStart(64, '0')

    // --- dataフィールド組み立て ---
    val dataForInfura =
        "0x" + methodId +
                proofOffset +
                publicInputsOffset +
                proofLengthPadded +
                proofDataPadded +
                publicInputsCount +
                publicInputsHex

    return dataForInfura
}