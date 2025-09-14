package org.ethtokyo.hackathon.anastasia.ui.home

import android.os.Bundle
import android.view.*
import android.widget.Toast
import androidx.core.view.MenuHost
import androidx.core.view.MenuProvider
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.navigation.fragment.findNavController
import androidx.recyclerview.widget.LinearLayoutManager
import org.ethtokyo.hackathon.anastasia.R
import org.ethtokyo.hackathon.anastasia.data.CertificateInfo
import org.ethtokyo.hackathon.anastasia.databinding.FragmentHomeBinding

class HomeFragment : Fragment() {

    private var _binding: FragmentHomeBinding? = null
    private val binding get() = _binding!!

    private lateinit var homeViewModel: HomeViewModel
    private lateinit var certificateAdapter: CertificateAdapter

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        homeViewModel = ViewModelProvider(this)[HomeViewModel::class.java]
        _binding = FragmentHomeBinding.inflate(inflater, container, false)

        setupMenu()
        setupRecyclerView()
        setupObservers()
        setupFab()

        return binding.root
    }

    override fun onResume() {
        super.onResume()
        // Refresh certificates when returning to this screen
        homeViewModel.refreshCertificates()
    }

    private fun setupMenu() {
        val menuHost: MenuHost = requireActivity()
        menuHost.addMenuProvider(object : MenuProvider {
            override fun onCreateMenu(menu: Menu, menuInflater: MenuInflater) {
                menuInflater.inflate(R.menu.home_menu, menu)
            }

            override fun onMenuItemSelected(menuItem: MenuItem): Boolean {
                return when (menuItem.itemId) {
                    R.id.action_proof_generation -> {
                        if (homeViewModel.hasGeneratedKey()) {
                            findNavController().navigate(R.id.action_home_to_proof_generation)
                        } else {
                            Toast.makeText(context, "First, you need to generate a key.", Toast.LENGTH_SHORT).show()
                        }
                        true
                    }
                    else -> false
                }
            }
        }, viewLifecycleOwner, Lifecycle.State.RESUMED)
    }

    private fun setupRecyclerView() {
        certificateAdapter = CertificateAdapter(emptyList()) { certificate ->
            onCertificateClick(certificate)
        }

        binding.recyclerCertificates.apply {
            layoutManager = LinearLayoutManager(context)
            adapter = certificateAdapter
        }
    }

    private fun setupObservers() {
        homeViewModel.certificates.observe(viewLifecycleOwner) { certificates ->
            certificateAdapter.updateCertificates(certificates)
            updateEmptyState(certificates.isEmpty())
            updateFabVisibility(certificates.isEmpty())
        }
    }

    private fun updateFabVisibility(isEmpty: Boolean) {
        // FABは鍵管理画面でデータが空の場合のみ表示
        binding.fabAddKey.visibility = if (isEmpty) View.VISIBLE else View.GONE
    }

    private fun setupFab() {
        binding.fabAddKey.setOnClickListener {
            findNavController().navigate(R.id.action_home_to_key_generation)
        }
    }

    private fun updateEmptyState(isEmpty: Boolean) {
        binding.tvEmptyMessage.visibility = if (isEmpty) View.VISIBLE else View.GONE
        binding.recyclerCertificates.visibility = if (isEmpty) View.GONE else View.VISIBLE
    }

    private fun onCertificateClick(certificate: CertificateInfo) {
        // TODO: Pass certificate data to detail screen
        findNavController().navigate(R.id.action_home_to_certificate_detail)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}