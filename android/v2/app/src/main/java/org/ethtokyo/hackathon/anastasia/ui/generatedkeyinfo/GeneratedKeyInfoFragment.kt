package org.ethtokyo.hackathon.anastasia.ui.generatedkeyinfo

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import androidx.navigation.fragment.findNavController
import androidx.recyclerview.widget.LinearLayoutManager
import org.ethtokyo.hackathon.anastasia.R
import org.ethtokyo.hackathon.anastasia.databinding.FragmentGeneratedKeyInfoBinding

class GeneratedKeyInfoFragment : Fragment() {

    private var _binding: FragmentGeneratedKeyInfoBinding? = null
    private val binding get() = _binding!!

    private lateinit var viewModel: GeneratedKeyInfoViewModel
    private lateinit var certificateAdapter: CertificateChainAdapter

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        viewModel = ViewModelProvider(this)[GeneratedKeyInfoViewModel::class.java]
        _binding = FragmentGeneratedKeyInfoBinding.inflate(inflater, container, false)

        setupRecyclerView()
        setupObservers()
        setupListeners()

        return binding.root
    }

    private fun setupRecyclerView() {
        certificateAdapter = CertificateChainAdapter(emptyArray())

        binding.recyclerCertificateChain.apply {
            layoutManager = LinearLayoutManager(context)
            adapter = certificateAdapter
        }
    }

    private fun setupObservers() {
        viewModel.certificates.observe(viewLifecycleOwner) { certificates ->
            certificateAdapter.updateCertificates(certificates)
        }
    }

    private fun setupListeners() {
        binding.btnFinish.setOnClickListener {
            findNavController().navigate(R.id.action_generated_key_info_to_home)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}