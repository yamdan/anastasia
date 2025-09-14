package org.ethtokyo.hackathon.anastasia.ui.dashboard

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import org.ethtokyo.hackathon.anastasia.data.VCInfo

class DashboardViewModel : ViewModel() {

    private val _vcItems = MutableLiveData<List<VCInfo>>()
    val vcItems: LiveData<List<VCInfo>> = _vcItems

    init {
        loadDummyVCs()
    }

    private fun loadDummyVCs() {
        val dummyVCs = listOf(
            VCInfo(
                id = "1",
                title = "Digital Identity Credential",
                issuer = "Government Identity Authority",
                status = "Valid",
                issuedDate = "2024-01-15"
            ),
            VCInfo(
                id = "2",
                title = "Educational Certificate",
                issuer = "University of Technology",
                status = "Valid",
                issuedDate = "2023-12-10"
            ),
            VCInfo(
                id = "3",
                title = "Professional License",
                issuer = "Professional Certification Board",
                status = "Valid",
                issuedDate = "2024-02-20"
            ),
            VCInfo(
                id = "4",
                title = "Health Insurance Credential",
                issuer = "National Health Service",
                status = "Expired",
                issuedDate = "2023-06-01"
            )
        )
        _vcItems.value = dummyVCs
    }
}