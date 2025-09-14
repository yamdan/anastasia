package org.ethtokyo.hackathon.anastasia.ui.certificatedetail

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import org.ethtokyo.hackathon.anastasia.Constants
import org.ethtokyo.hackathon.anastasia.core.ECKeystoreHelper
import org.ethtokyo.hackathon.anastasia.databinding.FragmentCertificateDetailBinding
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.*

class CertificateDetailFragment : Fragment() {

    private var _binding: FragmentCertificateDetailBinding? = null
    private val binding get() = _binding!!
    private val keystoreHelper = ECKeystoreHelper()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentCertificateDetailBinding.inflate(inflater, container, false)

        val certificateIndex = arguments?.getInt("certificateIndex", -1) ?: -1
        displayCertificateDetails(certificateIndex)

        return binding.root
    }

    private fun displayCertificateDetails(certificateIndex: Int) {
        try {
            val certificateChain = keystoreHelper.getAttestationCertificate(Constants.KEY_ALIAS)
            if (certificateChain != null && certificateIndex >= 0 && certificateIndex < certificateChain.size) {
                val certificate = certificateChain[certificateIndex] as? X509Certificate
                if (certificate != null) {
                    val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())

                    binding.tvSubjectValue.text = certificate.subjectX500Principal.name
                    binding.tvIssuerValue.text = certificate.issuerX500Principal.name
                    binding.tvSerialValue.text = certificate.serialNumber.toString(16).uppercase()
                    binding.tvValidityFrom.text = "Valid From: ${dateFormat.format(certificate.notBefore)}"
                    binding.tvValidityTo.text = "Valid To: ${dateFormat.format(certificate.notAfter)}"
                } else {
                    displayErrorDetails()
                }
            } else {
                displayErrorDetails()
            }
        } catch (e: Exception) {
            displayErrorDetails()
        }
    }

    private fun displayErrorDetails() {
        binding.tvSubjectValue.text = "Unable to load certificate details"
        binding.tvIssuerValue.text = "Error occurred"
        binding.tvSerialValue.text = "N/A"
        binding.tvValidityFrom.text = "N/A"
        binding.tvValidityTo.text = "N/A"
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}