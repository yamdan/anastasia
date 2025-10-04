package org.ethtokyo.hackathon.anastasia.ui.certificatedetail

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import org.ethtokyo.hackathon.anastasia.Constants
import org.ethtokyo.hackathon.anastasia.core.ECKeystoreHelper
import org.ethtokyo.hackathon.anastasia.data.CertificateDetailItem
import org.ethtokyo.hackathon.anastasia.databinding.FragmentCertificateDetailBinding
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.*

class CertificateDetailFragment : Fragment() {

    private var _binding: FragmentCertificateDetailBinding? = null
    private val binding get() = _binding!!
    private val keystoreHelper = ECKeystoreHelper()
    private lateinit var adapter: CertificateDetailAdapter

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentCertificateDetailBinding.inflate(inflater, container, false)

        setupRecyclerView()

        val certificateIndex = arguments?.getInt("certificateIndex", -1) ?: -1
        displayCertificateDetails(certificateIndex)

        return binding.root
    }

    private fun setupRecyclerView() {
        adapter = CertificateDetailAdapter(emptyList())
        binding.recyclerCertificateDetails.apply {
            layoutManager = LinearLayoutManager(requireContext())
            adapter = this@CertificateDetailFragment.adapter
        }
    }

    private fun displayCertificateDetails(certificateIndex: Int) {
        try {
            val certificateChain = keystoreHelper.getAttestationCertificate(Constants.KEY_ALIAS)
            if (certificateChain != null && certificateIndex >= 0 && certificateIndex < certificateChain.size) {
                val certificate = certificateChain[certificateIndex] as? X509Certificate
                if (certificate != null) {
                    val detailItems = buildDetailItems(certificate)
                    adapter.updateDetails(detailItems)
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

    private fun buildDetailItems(certificate: X509Certificate): List<CertificateDetailItem> {
        val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())

        return listOf(
            CertificateDetailItem(
                title = "Subject",
                value = certificate.subjectX500Principal.name
            ),
            CertificateDetailItem(
                title = "Issuer",
                value = certificate.issuerX500Principal.name
            ),
            CertificateDetailItem(
                title = "Serial Number",
                value = certificate.serialNumber.toString(16).uppercase()
            ),
            CertificateDetailItem(
                title = "Valid From",
                value = dateFormat.format(certificate.notBefore)
            ),
            CertificateDetailItem(
                title = "Valid To",
                value = dateFormat.format(certificate.notAfter)
            )
        )
    }

    private fun displayErrorDetails() {
        val errorItems = listOf(
            CertificateDetailItem(
                title = "Error",
                value = "Unable to load certificate details"
            )
        )
        adapter.updateDetails(errorItems)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}