package org.ethtokyo.hackathon.anastasia.ui.home

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import org.ethtokyo.hackathon.anastasia.R
import org.ethtokyo.hackathon.anastasia.data.CertificateInfo

class CertificateAdapter(
    private var certificates: List<CertificateInfo>,
    private val onCertificateClick: (CertificateInfo) -> Unit
) : RecyclerView.Adapter<CertificateAdapter.CertificateViewHolder>() {

    class CertificateViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val subjectText: TextView = itemView.findViewById(R.id.tv_certificate_subject)
        val issuerText: TextView = itemView.findViewById(R.id.tv_certificate_issuer)
        val typeText: TextView = itemView.findViewById(R.id.tv_certificate_type)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): CertificateViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_certificate, parent, false)
        return CertificateViewHolder(view)
    }

    override fun onBindViewHolder(holder: CertificateViewHolder, position: Int) {
        val certificate = certificates[position]

        holder.subjectText.text = certificate.subject
        holder.issuerText.text = "Issuer: ${certificate.issuer}"
        holder.typeText.text = if (certificate.isEndEntity) "End Entity Certificate" else "X.509 Certificate"

        holder.itemView.setOnClickListener {
            onCertificateClick(certificate)
        }
    }

    override fun getItemCount(): Int = certificates.size

    fun updateCertificates(newCertificates: List<CertificateInfo>) {
        certificates = newCertificates
        notifyDataSetChanged()
    }
}