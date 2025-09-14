package com.example.moproapp

import android.util.Log
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.json.JSONObject
import uniffi.mopro.CircuitMeta
import uniffi.mopro.generateNoirProof
import uniffi.mopro.verifyNoirProof
import uniffi.mopro.getNoirVerificationKey
import uniffi.mopro.prove
import java.io.File
import java.io.InputStream

fun bytes(vararg ints: Int): ByteArray =
    ints.map { it.toByte() }.toByteArray()

@Composable
fun NoirComponent() {
    val context = LocalContext.current
    var provingTime by remember { mutableStateOf("") }
    var proofResult by remember { mutableStateOf("") }
    var verificationTime by remember { mutableStateOf("") }
    var verificationResult by remember { mutableStateOf("") }
    var proofBytes by remember { mutableStateOf<ByteArray?>(null) }
    var verificationKey by remember { mutableStateOf<ByteArray?>(null) }

    // Status states
    var isGeneratingProof by remember { mutableStateOf(false) }
    var isVerifyingProof by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf("Ready to generate proof") }

    val circuitFile = getFilePathFromAssets("es256_ca.json")
    val srsFile = getFilePathFromAssets("common.srs")
    val vkFile = getFilePathFromAssets("es256_ca.vk")
    
    Box(modifier = Modifier.fillMaxSize().padding(16.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = "ES256-CA Verification",
                modifier = Modifier.padding(bottom = 20.dp),
                fontWeight = FontWeight.Bold,
                fontSize = 22.sp
            )

            // Status message with prominent styling
            Text(
                text = statusMessage,
                modifier = Modifier.padding(bottom = 24.dp),
                textAlign = TextAlign.Center,
                fontSize = 16.sp,
                fontWeight = if (isGeneratingProof || isVerifyingProof) FontWeight.Bold else FontWeight.Normal
            )

            // Progress indicator when operations are running
            if (isGeneratingProof || isVerifyingProof) {
                CircularProgressIndicator(
                    modifier = Modifier.padding(bottom = 16.dp)
                )
            }

            Button(
                onClick = {
                    isGeneratingProof = true
                    provingTime = ""
                    proofResult = ""
                    statusMessage = "Generating proof... This may take some time"

                    Thread(
                        Runnable {
                            try {
                                val cert = bytes(
                                    0x30, 0x82, 0x01, 0xe6, 0x30, 0x82, 0x01, 0x8c, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x11, 0x00, 0xe5, 0xbf, 0xa9, 0x77, 0x15, 0xc1, 0xcb, 0x11, 0x70, 0xc3, 0x0e, 0x01, 0x33, 0x1e, 0xef, 0x42, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x29, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x4c, 0x4c, 0x43, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x44, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x43, 0x41, 0x33, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x38, 0x32, 0x31, 0x31, 0x37, 0x32, 0x37, 0x30, 0x34, 0x5a, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x39, 0x31, 0x36, 0x31, 0x35, 0x32, 0x30, 0x31, 0x30, 0x5a, 0x30, 0x3f, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x20, 0x65, 0x35, 0x62, 0x66, 0x61, 0x39, 0x37, 0x37, 0x31, 0x35, 0x63, 0x31, 0x63, 0x62, 0x31, 0x31, 0x37, 0x30, 0x63, 0x33, 0x30, 0x65, 0x30, 0x31, 0x33, 0x33, 0x31, 0x65, 0x65, 0x66, 0x34, 0x32, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x09, 0x53, 0x74, 0x72, 0x6f, 0x6e, 0x67, 0x42, 0x6f, 0x78, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xa3, 0x30, 0xd2, 0x88, 0x45, 0xc2, 0xf4, 0xb1, 0x60, 0xa7, 0xa5, 0xa8, 0xec, 0x1e, 0x46, 0x21, 0x31, 0x18, 0x5e, 0x25, 0xba, 0x48, 0x7e, 0xba, 0x2f, 0xbb, 0x41, 0xd7, 0x18, 0xa7, 0xa6, 0xbf, 0xd7, 0x87, 0x8d, 0xc6, 0x36, 0xe4, 0x1e, 0xa4, 0xe2, 0x51, 0x6a, 0xa9, 0xc4, 0xf7, 0x1f, 0xce, 0x15, 0xf5, 0xd2, 0x48, 0x34, 0x05, 0x82, 0x56, 0x99, 0x72, 0x5c, 0xb1, 0x3c, 0xeb, 0x47, 0xcd, 0xa3, 0x7f, 0x30, 0x7d, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x83, 0x29, 0xbe, 0xbb, 0x68, 0xbc, 0x24, 0xed, 0x89, 0x38, 0x4d, 0xb4, 0xf1, 0x94, 0x6c, 0x20, 0xd7, 0x95, 0x9a, 0x05, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xfe, 0x62, 0x6c, 0xdc, 0x2a, 0xe5, 0x80, 0xe7, 0x19, 0x6a, 0xca, 0x23, 0xdd, 0x23, 0xf1, 0x39, 0x02, 0x46, 0xa8, 0xa5, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x02, 0x04, 0x30, 0x1a, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x1e, 0x04, 0x0c, 0xa2, 0x01, 0x18, 0x20, 0x03, 0x66, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xc9, 0x77, 0x3e, 0x28, 0xaa, 0x2b, 0x6c, 0x2a, 0xe5, 0x4b, 0xf0, 0x9f, 0xaa, 0xdf, 0x64, 0xc8, 0x23, 0x99, 0xcb, 0x1a, 0xb6, 0x6e, 0xa9, 0x07, 0x24, 0x3d, 0x9b, 0x83, 0x3a, 0x9a, 0x57, 0xd2, 0x02, 0x20, 0x21, 0xad, 0x97, 0xb8, 0x34, 0x04, 0x03, 0x56, 0xe1, 0x4e, 0x15, 0x5c, 0x78, 0x14, 0x91, 0x7a, 0xa3, 0x76, 0x55, 0x50, 0xf9, 0x0b, 0x0c, 0x5d, 0x0b, 0x5b, 0xbe, 0x43, 0xef, 0xcc, 0x31, 0xa3
                                )
                                val authorityKeyId = bytes(
                                    0xfe, 0x62, 0x6c, 0xdc, 0x2a, 0xe5, 0x80, 0xe7, 0x19, 0x6a, 0xca, 0x23, 0xdd, 0x23, 0xf1, 0x39, 0x02, 0x46, 0xa8, 0xa5
                                )
                                val issuerPkX = bytes(
                                    0x29, 0xc2, 0xef, 0x24, 0xa4, 0xbe, 0x89, 0xfd, 0x51, 0x35, 0x89, 0x24, 0xb3, 0x2e, 0x38, 0xd2, 0x5b, 0x64, 0x9e, 0x4e, 0x96, 0xff, 0x0b, 0x6f, 0x6b, 0xe2, 0x12, 0x87, 0x1b, 0xf5, 0x26, 0x27
                                )
                                val issuerPkY = bytes(
                                    0x9a, 0x9d, 0x6b, 0x56, 0x68, 0x29, 0xbf, 0x3a, 0xf8, 0xfe, 0xe0, 0x50, 0x94, 0x3f, 0xbb, 0x70, 0xab, 0xf5, 0xb1, 0xb3, 0x5a, 0xc1, 0xe3, 0xb8, 0x95, 0xee, 0x2e, 0xc0, 0xa8, 0x5a, 0xfb, 0xd2
                                )
                                val prevCmt = "0ede28f511104f08069e07986707873be5cbba917f02f02407ad1fdd6838679b"
                                val prevCmtR = "deadbeef"

                                statusMessage = "Generating proof with verification key..."
                                val startTime = System.currentTimeMillis()
                                val result = prove(
                                    CircuitMeta(
                                        "ES256-CA",
                                        circuitFile,
                                        vkFile,
                                        srsFile,
                                    ),
                                    cert,
                                    authorityKeyId,
                                    issuerPkX,
                                    issuerPkY,
                                    prevCmt,
                                    prevCmtR,
                                )
                                val proof = result.proof
                                val nextCmt = result.nextCmt
                                val nextCmtR = result.nextCmtR
                                val endTime = System.currentTimeMillis()
                                val duration = endTime - startTime

                                Log.w(null, proof)
                                Log.w(null, nextCmt)
                                Log.w(null, nextCmtR)

                                provingTime = "Proving time: $duration ms"
                                proofResult = "Proof generated: ${proof.length} hexes"
                                statusMessage = "Proof generation completed"
                            } catch (e: Exception) {
                                provingTime = "Proving failed"
                                proofResult = "Error: ${e.message}"
                                statusMessage = "Proof generation failed"
                                e.printStackTrace()
                            } finally {
                                isGeneratingProof = false
                            }
                        }
                    ).start()
                },
                modifier = Modifier.padding(top = 20.dp),
                enabled = !isGeneratingProof && !isVerifyingProof
            ) { 
                Text(text = "Generate Proof")
            }

            Spacer(modifier = Modifier.height(16.dp))

            Button(
                onClick = {
                    isVerifyingProof = true
                    verificationTime = ""
                    verificationResult = ""
                    statusMessage = "Verifying proof..."

                    Thread(
                        Runnable {
                            try {
                                proofBytes?.let { proof ->
                                    verificationKey?.let { vk ->
                                        val onChain = true  // Use Keccak for Solidity compatibility
                                        val lowMemoryMode = false

                                        val startTime = System.currentTimeMillis()
                                        val result = verifyNoirProof(
                                            circuitFile,
                                            proof,
                                            onChain,
                                            vk,
                                            lowMemoryMode
                                        )
                                        val endTime = System.currentTimeMillis()
                                        val duration = endTime - startTime

                                        verificationTime = "Verification time: $duration ms"
                                        verificationResult = "Verification result: $result"
                                        if (result)
                                            statusMessage = "Proof verified successfully!" 
                                        else 
                                            statusMessage = "Proof verification failed!"
                                    } ?: run {
                                        verificationResult = "No verification key available"
                                        statusMessage = "Please generate a proof first to get verification key"
                                    }
                                } ?: run {
                                    verificationResult = "No proof available"
                                    statusMessage = "Please generate a proof first"
                                }
                            } catch (e: Exception) {
                                verificationTime = "Verification failed"
                                verificationResult = "Error: ${e.message}"
                                statusMessage = "Proof verification error"
                                e.printStackTrace()
                            } finally {
                                isVerifyingProof = false
                            }
                        }
                    ).start()
                },
                modifier = Modifier.padding(top = 20.dp),
                enabled = !isGeneratingProof && !isVerifyingProof && proofBytes != null
            ) { 
                Text(text = "Verify Proof") 
            }

            Spacer(modifier = Modifier.height(40.dp))

            // Results displayed in a more organized way
            if (provingTime.isNotEmpty() || proofResult.isNotEmpty() || 
                verificationTime.isNotEmpty() || verificationResult.isNotEmpty()) {

                Text(
                    text = "Results",
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp,
                    modifier = Modifier.padding(bottom = 8.dp)
                )

                if (provingTime.isNotEmpty()) {
                    Text(
                        text = provingTime,
                        modifier = Modifier.padding(top = 4.dp).width(280.dp),
                        textAlign = TextAlign.Center
                    )
                }

                if (proofResult.isNotEmpty()) {
                    Text(
                        text = proofResult,
                        modifier = Modifier.padding(top = 4.dp).width(280.dp),
                        textAlign = TextAlign.Center
                    )
                }

                if (verificationTime.isNotEmpty()) {
                    Text(
                        text = verificationTime,
                        modifier = Modifier.padding(top = 4.dp).width(280.dp),
                        textAlign = TextAlign.Center
                    )
                }

                if (verificationResult.isNotEmpty()) {
                    Text(
                        text = verificationResult,
                        modifier = Modifier.padding(top = 4.dp).width(280.dp),
                        textAlign = TextAlign.Center,
                        fontWeight = if (verificationResult.contains("true")) FontWeight.Bold else FontWeight.Normal
                    )
                }
            }
        }
    }
} 