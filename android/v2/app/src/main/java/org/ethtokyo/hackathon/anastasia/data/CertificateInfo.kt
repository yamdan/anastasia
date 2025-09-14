package org.ethtokyo.hackathon.anastasia.data

import java.security.cert.Certificate

data class CertificateInfo(
    val certificate: Certificate,
    val subject: String,
    val issuer: String,
    val keyAlias: String,
    val isEndEntity: Boolean = false
)