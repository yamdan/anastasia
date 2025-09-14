package org.ethtokyo.hackathon.anastasia.ui.dashboard

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import org.ethtokyo.hackathon.anastasia.R
import org.ethtokyo.hackathon.anastasia.data.VCInfo

class VCAdapter(
    private var vcItems: List<VCInfo>,
    private val onVCClick: (VCInfo) -> Unit
) : RecyclerView.Adapter<VCAdapter.VCViewHolder>() {

    class VCViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val titleText: TextView = itemView.findViewById(R.id.tv_vc_title)
        val issuerText: TextView = itemView.findViewById(R.id.tv_vc_issuer)
        val statusText: TextView = itemView.findViewById(R.id.tv_vc_status)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VCViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_vc, parent, false)
        return VCViewHolder(view)
    }

    override fun onBindViewHolder(holder: VCViewHolder, position: Int) {
        val vcItem = vcItems[position]

        holder.titleText.text = vcItem.title
        holder.issuerText.text = "Issued by: ${vcItem.issuer}"
        holder.statusText.text = vcItem.status

        holder.itemView.setOnClickListener {
            onVCClick(vcItem)
        }
    }

    override fun getItemCount(): Int = vcItems.size

    fun updateVCs(newVCItems: List<VCInfo>) {
        vcItems = newVCItems
        notifyDataSetChanged()
    }
}