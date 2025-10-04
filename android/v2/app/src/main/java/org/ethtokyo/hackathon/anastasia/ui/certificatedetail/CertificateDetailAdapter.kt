package org.ethtokyo.hackathon.anastasia.ui.certificatedetail

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import org.ethtokyo.hackathon.anastasia.R
import org.ethtokyo.hackathon.anastasia.data.CertificateDetailItem

class CertificateDetailAdapter(
    private var detailItems: List<CertificateDetailItem>
) : RecyclerView.Adapter<CertificateDetailAdapter.DetailViewHolder>() {

    class DetailViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val titleText: TextView = itemView.findViewById(R.id.tv_detail_title)
        val valueText: TextView = itemView.findViewById(R.id.tv_detail_value)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): DetailViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_certificate_detail, parent, false)
        return DetailViewHolder(view)
    }

    override fun onBindViewHolder(holder: DetailViewHolder, position: Int) {
        val item = detailItems[position]
        holder.titleText.text = item.title
        holder.valueText.text = item.value
    }

    override fun getItemCount(): Int = detailItems.size

    fun updateDetails(newItems: List<CertificateDetailItem>) {
        detailItems = newItems
        notifyDataSetChanged()
    }
}