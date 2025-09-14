package org.ethtokyo.hackathon.anastasia.smart_contract

import org.ethtokyo.hackathon.anastasia.BuildConfig
import org.ethtokyo.hackathon.anastasia.Constants

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

fun resolveInfuraPath(): String {
    val apiKey = BuildConfig.SEPOLIA_API_KEY
    return joinPathToInfura(apiKey)
}

fun joinPathToInfura(path: String): String {
    val baseUrl = Constants.INFURA_ENDPOINT_URL.removeSuffix("/")
    val pathSegment = path.removePrefix("/")
    return "$baseUrl/$pathSegment"
}
