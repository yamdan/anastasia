package org.ethtokyo.hackathon.anastasia.ui.dashboard

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import androidx.recyclerview.widget.LinearLayoutManager
import org.ethtokyo.hackathon.anastasia.data.VCInfo
import org.ethtokyo.hackathon.anastasia.databinding.FragmentDashboardBinding

class DashboardFragment : Fragment() {

    private var _binding: FragmentDashboardBinding? = null
    private val binding get() = _binding!!

    private lateinit var dashboardViewModel: DashboardViewModel
    private lateinit var vcAdapter: VCAdapter

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        dashboardViewModel = ViewModelProvider(this)[DashboardViewModel::class.java]
        _binding = FragmentDashboardBinding.inflate(inflater, container, false)

        setupRecyclerView()
        setupObservers()

        return binding.root
    }

    private fun setupRecyclerView() {
        vcAdapter = VCAdapter(emptyList()) { vcItem ->
            onVCClick(vcItem)
        }

        binding.recyclerVcItems.apply {
            layoutManager = LinearLayoutManager(context)
            adapter = vcAdapter
        }
    }

    private fun setupObservers() {
        dashboardViewModel.vcItems.observe(viewLifecycleOwner) { vcItems ->
            vcAdapter.updateVCs(vcItems)
        }
    }

    private fun onVCClick(vcItem: VCInfo) {
        // VC items should not navigate as per requirements - do nothing
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}