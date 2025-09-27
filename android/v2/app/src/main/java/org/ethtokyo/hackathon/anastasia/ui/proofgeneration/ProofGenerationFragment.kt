package org.ethtokyo.hackathon.anastasia.ui.proofgeneration

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import androidx.navigation.fragment.findNavController
import org.ethtokyo.hackathon.anastasia.R
import org.ethtokyo.hackathon.anastasia.databinding.FragmentProofGenerationBinding
import org.ethtokyo.hackathon.anastasia.data.ProofGenerationPerformance

class ProofGenerationFragment : Fragment() {

    private var _binding: FragmentProofGenerationBinding? = null
    private val binding get() = _binding!!

    private lateinit var viewModel: ProofGenerationViewModel
    private var currentPerformance: ProofGenerationPerformance? = null
    private var currentProofResults: Array<uniffi.mopro.ProofResult>? = null
    private var hasNavigated = false

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        viewModel = ViewModelProvider(this)[ProofGenerationViewModel::class.java]
        _binding = FragmentProofGenerationBinding.inflate(inflater, container, false)

        setupObservers()
        setupListeners()

        return binding.root
    }

    private fun setupObservers() {
        viewModel.proofGenerationResult.observe(viewLifecycleOwner) { result ->
            if (result.isSuccess) {
                val proofResults = result.getOrNull()
                if (proofResults != null && proofResults.isNotEmpty()) {
                    currentProofResults = proofResults
                    navigateIfReady()
                } else {
                    Toast.makeText(context, "Proof generation failed: No proofs generated", Toast.LENGTH_LONG).show()
                    findNavController().navigate(R.id.action_proofGenerationFragment_to_navigation_key_management)
                }
            } else {
                val error = result.exceptionOrNull()?.message ?: "Proof generation failed"
                Toast.makeText(context, error, Toast.LENGTH_LONG).show()
                // Navigate back to home on error
                findNavController().navigate(R.id.action_proofGenerationFragment_to_navigation_key_management)
            }
        }

        viewModel.proofGenerationPerformance.observe(viewLifecycleOwner) { performance ->
            currentPerformance = performance
            navigateIfReady()
        }

        viewModel.isLoading.observe(viewLifecycleOwner) { isLoading ->
            binding.btnStart.isEnabled = !isLoading
            binding.progressBar.visibility = if (isLoading) View.VISIBLE else View.GONE

            if (isLoading) {
                binding.btnStart.text = "Processing..."
            } else {
                binding.btnStart.text = "Start"
            }
        }
    }

    private fun navigateIfReady() {
        val proofResults = currentProofResults
        val performance = currentPerformance

        if (proofResults != null && performance != null && !hasNavigated) {
            hasNavigated = true
            val proofs = proofResults.map { it.proof }.toTypedArray()
            val nextCmts = proofResults.map { it.nextCmt }.toTypedArray()
            val nextCmtRs = proofResults.map { it.nextCmtR }.toTypedArray()

            val action = ProofGenerationFragmentDirections.actionProofGenerationFragmentToProofCompletedFragment(
                proofs, nextCmts, nextCmtRs, performance
            )
            findNavController().navigate(action)
        }
    }

    private fun setupListeners() {
        binding.btnStart.setOnClickListener {
            hasNavigated = false
            currentProofResults = null
            currentPerformance = null
            viewModel.generateProof()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
