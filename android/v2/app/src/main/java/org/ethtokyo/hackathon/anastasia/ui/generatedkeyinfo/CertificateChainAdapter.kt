package org.ethtokyo.hackathon.anastasia.ui.generatedkeyinfo

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import org.ethtokyo.hackathon.anastasia.R
import java.security.cert.Certificate
import java.security.cert.X509Certificate

class CertificateChainAdapter(
    private var certificates: Array<Certificate>
) : RecyclerView.Adapter<CertificateChainAdapter.CertificateViewHolder>() {

    class CertificateViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val indexText: TextView = itemView.findViewById(R.id.tv_certificate_index)
        val subjectValue: TextView = itemView.findViewById(R.id.tv_subject_value)
        val issuerValue: TextView = itemView.findViewById(R.id.tv_issuer_value)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): CertificateViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_certificate_info, parent, false)
        return CertificateViewHolder(view)
    }

    override fun onBindViewHolder(holder: CertificateViewHolder, position: Int) {
        val certificate = certificates[position] as? X509Certificate

        holder.indexText.text = "Certificate $position"
        holder.subjectValue.text = certificate?.subjectX500Principal?.name ?: "Unknown Subject"
        holder.issuerValue.text = certificate?.issuerX500Principal?.name ?: "Unknown Issuer"
    }

    override fun getItemCount(): Int = certificates.size

    fun updateCertificates(newCertificates: Array<Certificate>) {
        certificates = newCertificates
        notifyDataSetChanged()
    }
}