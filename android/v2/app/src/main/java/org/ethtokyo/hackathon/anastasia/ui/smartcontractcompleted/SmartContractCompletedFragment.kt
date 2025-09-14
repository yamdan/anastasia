package org.ethtokyo.hackathon.anastasia.ui.smartcontractcompleted

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import androidx.navigation.fragment.navArgs
import org.ethtokyo.hackathon.anastasia.R
import org.ethtokyo.hackathon.anastasia.databinding.FragmentSmartContractCompletedBinding

class SmartContractCompletedFragment : Fragment() {

    private var _binding: FragmentSmartContractCompletedBinding? = null
    private val binding get() = _binding!!
    private val args: SmartContractCompletedFragmentArgs by navArgs()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentSmartContractCompletedBinding.inflate(inflater, container, false)

        binding.textViewResponseData.text = args.responseData

        binding.buttonFinish.setOnClickListener {
            findNavController().navigate(R.id.action_smartContractCompletedFragment_to_navigation_key_management)
        }

        return binding.root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
