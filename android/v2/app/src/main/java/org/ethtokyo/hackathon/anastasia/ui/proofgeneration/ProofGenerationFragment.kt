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

class ProofGenerationFragment : Fragment() {

    private var _binding: FragmentProofGenerationBinding? = null
    private val binding get() = _binding!!

    private lateinit var viewModel: ProofGenerationViewModel
    private var hasNavigated = false
    private var isNavigating = false

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
        viewModel.proofsGenerationResult.observe(viewLifecycleOwner) { result ->
            if (result.isSuccess) {
                val proofsResult = result.getOrNull()
                if (proofsResult != null && proofsResult.proofs.isNotEmpty() && !hasNavigated) {
                    hasNavigated = true
                    isNavigating = true

                    // 即座に画面遷移を実行
                    val action = ProofGenerationFragmentDirections.actionProofGenerationFragmentToProofCompletedFragment(
                        proofsResult
                    )
                    findNavController().navigate(action)

                    // 画面遷移後にローディング状態を解除
                    viewModel.onNavigationCompleted()
                } else if (!hasNavigated) {
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

        viewModel.isLoading.observe(viewLifecycleOwner) { isLoading ->
            binding.btnStart.isEnabled = !isLoading && !isNavigating
            binding.progressBar.visibility = if (isLoading) View.VISIBLE else View.GONE

            if (isLoading || isNavigating) {
                binding.btnStart.text = "Processing..."
            } else {
                binding.btnStart.text = "Start"
            }
        }

        viewModel.progressMessage.observe(viewLifecycleOwner) { message ->
            if (message.isNotEmpty()) {
                binding.tvProgressMessage.text = message
                binding.tvProgressMessage.visibility = View.VISIBLE
            } else {
                binding.tvProgressMessage.visibility = View.GONE
            }
        }
    }

    private fun setupListeners() {
        binding.btnStart.setOnClickListener {
            hasNavigated = false
            isNavigating = false
            binding.tvProgressMessage.visibility = View.GONE
            viewModel.generateProof()
        }
    }

    override fun onResume() {
        super.onResume()
        // 画面に戻ってきた時に状態をリセット
        if (hasNavigated) {
            hasNavigated = false
            isNavigating = false
            viewModel.resetState()

            // UIを強制的に更新
            updateUI()
        }
    }

    private fun updateUI() {
        binding.btnStart.isEnabled = true
        binding.btnStart.text = "Start"
        binding.progressBar.visibility = View.GONE
        binding.tvProgressMessage.visibility = View.GONE
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
