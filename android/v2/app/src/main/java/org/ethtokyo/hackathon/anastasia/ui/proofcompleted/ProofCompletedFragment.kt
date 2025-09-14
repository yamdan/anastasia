package org.ethtokyo.hackathon.anastasia.ui.proofcompleted

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
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
import uniffi.mopro.ProofResult

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

        // ProofResultオブジェクトを再構築
        val proofResults = Array(args.proofs.size) { i ->
            ProofResult(
                proof = args.proofs[i],
                nextCmt = args.nextCmts[i],
                nextCmtR = args.nextCmtRs[i]
            )
        }

        // 複数のproofを改行区切りで表示
        val proofsText = proofResults.joinToString("\n\n") { proofResult ->
            "Proof:\n${proofResult.proof}\n\nNext Commitment:\n${proofResult.nextCmt}\n\nNext Commitment R:\n${proofResult.nextCmtR}"
        }
        binding.textViewProof.text = proofsText

        setupListeners(proofResults, proofsText)
        setupObservers()

        return binding.root
    }

    private fun setupListeners(proofResults: Array<ProofResult>, proofsText: String) {
        binding.buttonYes.setOnClickListener {
            viewModel.recordProofs(proofResults)
        }
        binding.buttonNo.setOnClickListener {
            findNavController().navigate(R.id.action_proofCompletedFragment_to_navigation_key_management)
        }

        binding.textViewProof.setOnClickListener {
            copyToClipboard(proofsText)
        }
    }

    private fun copyToClipboard(text: String) {
        val clipboard = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("Proof Data", text)
        clipboard.setPrimaryClip(clip)
        Toast.makeText(requireContext(), "Proof data copied to clipboard", Toast.LENGTH_SHORT).show()
    }

    private fun setupObservers() {
        viewModel.postResult.observe(viewLifecycleOwner) { result ->
            if (result.isSuccess) {
                val allProofsResult = result.getOrNull()
                if (allProofsResult != null) {
                    // 常に次の画面に遷移し、結果の詳細を表示
                    val jsonData = allProofsResult.toJsonString()
                    val action = ProofCompletedFragmentDirections.actionProofCompletedFragmentToSmartContractCompletedFragment(jsonData)
                    findNavController().navigate(action)
                } else {
                    Toast.makeText(context, "No results received", Toast.LENGTH_LONG).show()
                    findNavController().navigate(R.id.action_proofCompletedFragment_to_navigation_key_management)
                }
            } else {
                Toast.makeText(context, "Failed to record proof: ${result.exceptionOrNull()?.message}", Toast.LENGTH_LONG).show()
                findNavController().navigate(R.id.action_proofCompletedFragment_to_navigation_key_management)
            }
        }

        viewModel.isLoading.observe(viewLifecycleOwner) { isLoading ->
            binding.buttonYes.isEnabled = !isLoading
            binding.buttonNo.isEnabled = !isLoading
            if (!isLoading) {
                binding.buttonYes.text = "YES"
            }
        }

        viewModel.progressMessage.observe(viewLifecycleOwner) { message ->
            if (message.isNotEmpty()) {
                binding.buttonYes.text = message
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
