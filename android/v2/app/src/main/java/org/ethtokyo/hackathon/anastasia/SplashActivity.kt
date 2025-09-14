package org.ethtokyo.hackathon.anastasia

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.appcompat.app.AppCompatActivity
import org.ethtokyo.hackathon.anastasia.databinding.ActivitySplashBinding

class SplashActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySplashBinding

    companion object {
        private const val SPLASH_DELAY = 2000L // 2 seconds
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivitySplashBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Hide action bar for splash screen
        supportActionBar?.hide()

        // Navigate to MainActivity after delay
        Handler(Looper.getMainLooper()).postDelayed({
            val intent = Intent(this, MainActivity::class.java)
            startActivity(intent)
            finish()
        }, SPLASH_DELAY)
    }
}