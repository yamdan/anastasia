package org.ethtokyo.hackathon.anastasia

import android.os.Bundle
import android.util.Log
import com.google.android.material.bottomnavigation.BottomNavigationView
import androidx.appcompat.app.AppCompatActivity
import androidx.navigation.findNavController
import androidx.navigation.ui.AppBarConfiguration
import androidx.navigation.ui.setupActionBarWithNavController
import androidx.navigation.ui.setupWithNavController
import org.ethtokyo.hackathon.anastasia.data.AppSettings
import org.ethtokyo.hackathon.anastasia.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)

        // Initialize app settings on startup
        Log.d("MainActivity", "Initializing AppSettings...")
        val appSettings = AppSettings.getInstance(this)
        Log.d("MainActivity", "AppSettings initialized. Testing values...")
        Log.d("MainActivity", "CA Address: '${appSettings.getCaCertVerifierAddressValue()}'")
        Log.d("MainActivity", "EE Address: '${appSettings.getEeCertVerifierAddressValue()}'")
        Log.d("MainActivity", "BuildConfig SC_ADDRESS_CA: '${BuildConfig.SC_ADDRESS_CA}'")
        Log.d("MainActivity", "BuildConfig SC_ADDRESS_EE: '${BuildConfig.SC_ADDRESS_EE}'")

        val navView: BottomNavigationView = binding.navView

        val navController = findNavController(R.id.nav_host_fragment_activity_main)
        // Passing each menu ID as a set of Ids because each
        // menu should be considered as top level destinations.
        val appBarConfiguration = AppBarConfiguration(
            setOf(
                R.id.navigation_key_management, R.id.navigation_vc_management, R.id.navigation_settings
            )
        )
        setupActionBarWithNavController(navController, appBarConfiguration)
        navView.setupWithNavController(navController)

        // Hide/show bottom navigation based on destination
        navController.addOnDestinationChangedListener { _, destination, _ ->
            when (destination.id) {
                R.id.navigation_key_management,
                R.id.navigation_vc_management,
                R.id.navigation_settings -> {
                    navView.visibility = android.view.View.VISIBLE
                }
                else -> {
                    navView.visibility = android.view.View.GONE
                }
            }
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        val navController = findNavController(R.id.nav_host_fragment_activity_main)
        return navController.navigateUp() || super.onSupportNavigateUp()
    }
}