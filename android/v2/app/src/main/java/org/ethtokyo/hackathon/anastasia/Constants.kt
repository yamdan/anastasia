package org.ethtokyo.hackathon.anastasia

object Constants {
    const val KEY_ALIAS = "secure-key";

    object SmartContract {
        const val CONNECT_TIMEOUT = 10L
        const val WRITE_TIMEOUT = 15L
        const val READ_TIMEOUT = 10L
        const val INFURA_ENDPOINT_URL = "https://sepolia.infura.io/v3/"
    }
}