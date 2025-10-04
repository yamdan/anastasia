package org.ethtokyo.hackathon.anastasia.ui.settings

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import org.ethtokyo.hackathon.anastasia.databinding.FragmentSettingsBinding

class SettingsFragment : Fragment() {

    private var _binding: FragmentSettingsBinding? = null
    private val binding get() = _binding!!

    private lateinit var settingsViewModel: SettingsViewModel

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        settingsViewModel = ViewModelProvider(this)[SettingsViewModel::class.java]

        _binding = FragmentSettingsBinding.inflate(inflater, container, false)
        val root: View = binding.root

        // Load saved settings
        settingsViewModel.loadSettings()

        // Observe settings data
        settingsViewModel.sepoliaApiKey.observe(viewLifecycleOwner) { apiKey ->
            binding.editTextSepoliaApiKey.setText(apiKey)
        }

        settingsViewModel.caCertVerifierAddress.observe(viewLifecycleOwner) { address ->
            binding.editTextCaCertVerifierAddress.setText(address)
        }

        settingsViewModel.eeCertVerifierAddress.observe(viewLifecycleOwner) { address ->
            binding.editTextEeCertVerifierAddress.setText(address)
        }

        settingsViewModel.eeCertLongVerifierAddress.observe(viewLifecycleOwner) { address ->
            binding.editTextEeCertLongVerifierAddress.setText(address)
        }

        // Save button click listener
        binding.buttonSave.setOnClickListener {
            val sepoliaApiKey = binding.editTextSepoliaApiKey.text.toString()
            val caCertVerifierAddress = binding.editTextCaCertVerifierAddress.text.toString()
            val eeCertVerifierAddress = binding.editTextEeCertVerifierAddress.text.toString()
            val eeCertLongVerifierAddress = binding.editTextEeCertLongVerifierAddress.text.toString()

            settingsViewModel.saveSettings(
                sepoliaApiKey,
                caCertVerifierAddress,
                eeCertVerifierAddress,
                eeCertLongVerifierAddress
            )

            Toast.makeText(context, "Settings saved successfully", Toast.LENGTH_SHORT).show()
        }

        return root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}