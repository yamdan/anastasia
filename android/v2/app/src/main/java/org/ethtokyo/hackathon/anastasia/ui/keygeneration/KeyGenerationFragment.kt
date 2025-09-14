package org.ethtokyo.hackathon.anastasia.ui.keygeneration

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import androidx.navigation.fragment.findNavController
import org.ethtokyo.hackathon.anastasia.R
import org.ethtokyo.hackathon.anastasia.databinding.FragmentKeyGenerationBinding

class KeyGenerationFragment : Fragment() {

    private var _binding: FragmentKeyGenerationBinding? = null
    private val binding get() = _binding!!

    private lateinit var viewModel: KeyGenerationViewModel

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        viewModel = ViewModelProvider(this)[KeyGenerationViewModel::class.java]
        _binding = FragmentKeyGenerationBinding.inflate(inflater, container, false)

        setupObservers()
        setupListeners()

        return binding.root
    }

    private fun setupObservers() {
        viewModel.keyGenerationResult.observe(viewLifecycleOwner) { result ->
            if (result.isSuccess) {
                // Navigate to generated key info screen
                findNavController().navigate(R.id.action_key_generation_to_generated_key_info)
            } else {
                val error = result.exceptionOrNull()?.message ?: "Key generation failed"
                Toast.makeText(context, error, Toast.LENGTH_LONG).show()
            }
        }

        viewModel.isLoading.observe(viewLifecycleOwner) { isLoading ->
            binding.btnProceed.isEnabled = !isLoading
            if (isLoading) {
                binding.btnProceed.text = "Generating..."
            } else {
                binding.btnProceed.text = "Proceed"
            }
        }
    }

    private fun setupListeners() {
        binding.btnProceed.setOnClickListener {
            val challenge = binding.etChallenge.text.toString()
            viewModel.generateKey(challenge.takeIf { it.isNotBlank() })
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}