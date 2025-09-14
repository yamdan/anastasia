package org.ethtokyo.hackathon.anastasia.ui.certificatedetail

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.navArgs
import org.ethtokyo.hackathon.anastasia.databinding.FragmentCertificateDetailBinding
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.*

class CertificateDetailFragment : Fragment() {

    private var _binding: FragmentCertificateDetailBinding? = null
    private val binding get() = _binding!!

    // TODO: Add Safe Args for passing certificate data
    // private val args: CertificateDetailFragmentArgs by navArgs()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentCertificateDetailBinding.inflate(inflater, container, false)

        // TODO: Get certificate from arguments and display details
        displayMockCertificateDetails()

        return binding.root
    }

    private fun displayMockCertificateDetails() {
        // For now, display mock data
        binding.tvSubjectValue.text = "CN=Android Keystore Key, O=Android, C=US"
        binding.tvIssuerValue.text = "CN=Android Keystore, O=Google, C=US"
        binding.tvSerialValue.text = "1234567890ABCDEF"
        binding.tvValidityFrom.text = "Valid From: 2024-01-01"
        binding.tvValidityTo.text = "Valid To: 2025-01-01"
    }

    private fun displayCertificateDetails(certificate: X509Certificate) {
        val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())

        binding.tvSubjectValue.text = certificate.subjectX500Principal.name
        binding.tvIssuerValue.text = certificate.issuerX500Principal.name
        binding.tvSerialValue.text = certificate.serialNumber.toString(16).uppercase()
        binding.tvValidityFrom.text = "Valid From: ${dateFormat.format(certificate.notBefore)}"
        binding.tvValidityTo.text = "Valid To: ${dateFormat.format(certificate.notAfter)}"
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}