package org.ethtokyo.hackathon.anastasia.ui.proofgeneration

import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
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
        setupUrlInputValidation()

        return binding.root
    }

    private fun setupObservers() {
        viewModel.proofGenerationResult.observe(viewLifecycleOwner) { result ->
            if (result.isSuccess) {
                val proofsResult = result.getOrNull()
                if (proofsResult != null && proofsResult.keyAttestationJwt.isNotEmpty() && !hasNavigated) {
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
                    Toast.makeText(context, "Key attestation JWT generation failed: No proofs generated", Toast.LENGTH_LONG).show()
                    findNavController().navigate(R.id.action_proofGenerationFragment_to_navigation_key_management)
                }
            } else {
                val error = result.exceptionOrNull()?.message ?: "Key attestation JWT generation failed"
                Toast.makeText(context, error, Toast.LENGTH_LONG).show()
                // Navigate back to home on error
                findNavController().navigate(R.id.action_proofGenerationFragment_to_navigation_key_management)
            }
        }

        viewModel.isLoading.observe(viewLifecycleOwner) { isLoading ->
            val hasInput = !binding.etUrlInput.text.isNullOrBlank()
            binding.btnStart.isEnabled = !isLoading && !isNavigating && hasInput
            binding.btnStart384.isEnabled = !isLoading && !isNavigating && hasInput
            binding.btnStart384Composed.isEnabled = !isLoading && !isNavigating && hasInput
            binding.btnStart384ComposedAka.isEnabled = !isLoading && !isNavigating && hasInput
            binding.progressBar.visibility = if (isLoading) View.VISIBLE else View.GONE

            if (isLoading || isNavigating) {
                binding.btnStart.text = "Processing..."
                binding.btnStart384.text = "Processing..."
                binding.btnStart384Composed.text = "Processing..."
                binding.btnStart384ComposedAka.text = "Processing..."
            } else {
                binding.btnStart.text = "Start with ES256"
                binding.btnStart384.text = "Start with ES384 and ES256"
                binding.btnStart384Composed.text = "Start with ES384 and ES256 (Composed Circuits)"
                binding.btnStart384ComposedAka.text = "Start with ES384 and ES256 (Optimized Circuits)"
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

    private fun setupUrlInputValidation() {
        // 初期状態でボタンを非活性化
        binding.btnStart.isEnabled = false
        binding.btnStart384.isEnabled = false
        binding.btnStart384Composed.isEnabled = false
        binding.btnStart384ComposedAka.isEnabled = false

        // URL入力フィールドの変更を監視
        binding.etUrlInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}

            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                // 入力がある場合のみボタンを活性化
                val hasInput = !s.isNullOrBlank()
                val isLoading = viewModel.isLoading.value ?: false
                binding.btnStart.isEnabled = hasInput && !isLoading && !isNavigating
                binding.btnStart384.isEnabled = hasInput && !isLoading && !isNavigating
                binding.btnStart384Composed.isEnabled = hasInput && !isLoading && !isNavigating
                binding.btnStart384ComposedAka.isEnabled = hasInput && !isLoading && !isNavigating
            }

            override fun afterTextChanged(s: Editable?) {}
        })
    }

    private fun setupListeners() {
        binding.btnStart.setOnClickListener {
            val url = binding.etUrlInput.text.toString()

            // 3つの要素を表示
            binding.tvProcessTimeMessage.visibility = View.VISIBLE
            binding.proofGenerationImage.visibility = View.VISIBLE

            hasNavigated = false
            isNavigating = false
            binding.tvProgressMessage.visibility = View.GONE
            viewModel.generateProof(url, "es256")
        }

        binding.btnStart384.setOnClickListener {
            val url = binding.etUrlInput.text.toString()

            // 3つの要素を表示
            binding.tvProcessTimeMessage.visibility = View.VISIBLE
            binding.proofGenerationImage.visibility = View.VISIBLE

            hasNavigated = false
            isNavigating = false
            binding.tvProgressMessage.visibility = View.GONE
            viewModel.generateProof(url, "es384")
        }

        binding.btnStart384Composed.setOnClickListener {
            val url = binding.etUrlInput.text.toString()

            // 3つの要素を表示
            binding.tvProcessTimeMessage.visibility = View.VISIBLE
            binding.proofGenerationImage.visibility = View.VISIBLE

            hasNavigated = false
            isNavigating = false
            binding.tvProgressMessage.visibility = View.GONE
            viewModel.generateProof(url, "es384-composed")
        }

        binding.btnStart384ComposedAka.setOnClickListener {
            val url = binding.etUrlInput.text.toString()

            // 3つの要素を表示
            binding.tvProcessTimeMessage.visibility = View.VISIBLE
            binding.proofGenerationImage.visibility = View.VISIBLE

            hasNavigated = false
            isNavigating = false
            binding.tvProgressMessage.visibility = View.GONE
            viewModel.generateProof(url, "es384-composed-aka")
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
        val hasInput = !binding.etUrlInput.text.isNullOrBlank()
        binding.btnStart.isEnabled = hasInput
        binding.btnStart384.isEnabled = hasInput
        binding.btnStart384Composed.isEnabled = hasInput
        binding.btnStart384ComposedAka.isEnabled = hasInput
        binding.btnStart.text = "Start with ES256"
        binding.btnStart384.text = "Start with ES384 and ES256"
        binding.btnStart384Composed.text = "Start with ES384 and ES256 (Composed Circuits)"
        binding.btnStart384ComposedAka.text = "Start with ES384 and ES256 (Optimized Circuits)"
        binding.progressBar.visibility = View.GONE
        binding.tvProgressMessage.visibility = View.GONE
        binding.tvProcessTimeMessage.visibility = View.GONE
        binding.proofGenerationImage.visibility = View.GONE
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
