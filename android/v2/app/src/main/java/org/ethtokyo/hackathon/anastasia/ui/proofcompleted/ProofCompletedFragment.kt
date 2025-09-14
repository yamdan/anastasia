package org.ethtokyo.hackathon.anastasia.ui.proofcompleted

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import androidx.navigation.fragment.findNavController
import androidx.navigation.fragment.navArgs
import org.ethtokyo.hackathon.anastasia.R
import org.ethtokyo.hackathon.anastasia.databinding.FragmentProofCompletedBinding

class ProofCompletedFragment : Fragment() {

    private var _binding: FragmentProofCompletedBinding? = null
    private val binding get() = _binding!!

    private lateinit var viewModel: ProofCompletedViewModel
    private val args: ProofCompletedFragmentArgs by navArgs()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        viewModel = ViewModelProvider(this)[ProofCompletedViewModel::class.java]
        _binding = FragmentProofCompletedBinding.inflate(inflater, container, false)

        // 複数のproofを改行区切りで表示
        val proofsText = args.proofs.joinToString("\n\n") { proof ->
            "Proof:\n$proof"
        }
        binding.textViewProof.text = proofsText

        setupListeners()
        setupObservers()

        return binding.root
    }

    private fun setupListeners() {
        binding.buttonYes.setOnClickListener {
            viewModel.recordProofs(args.proofs)
        }
        binding.buttonNo.setOnClickListener {
            findNavController().navigate(R.id.action_proofCompletedFragment_to_navigation_key_management)
        }
    }

    private fun setupObservers() {
        viewModel.postResult.observe(viewLifecycleOwner) { result ->
            if (result.isSuccess) {
                val response = result.getOrNull()
                // Navigate to smart contract completed screen
                val action = ProofCompletedFragmentDirections.actionProofCompletedFragmentToSmartContractCompletedFragment(response ?: "")
                findNavController().navigate(action)
            } else {
                Toast.makeText(context, "Failed to record proof: ${result.exceptionOrNull()?.message}", Toast.LENGTH_LONG).show()
                findNavController().navigate(R.id.action_proofCompletedFragment_to_navigation_key_management)
            }
        }

        viewModel.isLoading.observe(viewLifecycleOwner) { isLoading ->
            binding.buttonYes.isEnabled = !isLoading
            binding.buttonNo.isEnabled = !isLoading
            if (isLoading) {
                binding.buttonYes.text = "Processing..."
            } else {
                binding.buttonYes.text = "YES"
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
