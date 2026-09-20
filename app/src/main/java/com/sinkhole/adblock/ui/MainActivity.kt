package com.sinkhole.adblock.ui

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.format.DateFormat
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.sinkhole.adblock.R
import com.sinkhole.adblock.blocklist.BlocklistManager
import com.sinkhole.adblock.data.PrefsManager
import com.sinkhole.adblock.databinding.ActivityMainBinding
import com.sinkhole.adblock.vpn.SinkholeVpnService
import java.util.Date
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var prefs: PrefsManager
    private lateinit var blocklistManager: BlocklistManager

    private val mainHandler = Handler(Looper.getMainLooper())
    private val backgroundExecutor = Executors.newSingleThreadExecutor()
    private var refreshRunnable: Runnable? = null

    private val vpnPrepareLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startProtection()
        } else {
            binding.protectionSwitch.isChecked = false
            Toast.makeText(this, R.string.vpn_permission_denied, Toast.LENGTH_LONG).show()
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* no-op: foreground service still runs even if declined */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        prefs = PrefsManager(this)
        blocklistManager = BlocklistManager(this, prefs)
        backgroundExecutor.execute { blocklistManager.loadInitial() }

        requestNotificationPermissionIfNeeded()

        binding.protectionSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) requestEnableProtection() else stopProtection()
        }

        binding.updateBlocklistButton.setOnClickListener { updateBlocklist() }
        binding.viewLogsButton.setOnClickListener {
            startActivity(Intent(this, LogViewerActivity::class.java))
        }
        binding.privateDnsWarning.setOnClickListener { openNetworkSettings() }

        binding.minimalNotificationSwitch.isChecked = prefs.minimalNotification
        binding.minimalNotificationSwitch.setOnCheckedChangeListener { _, isChecked ->
            prefs.minimalNotification = isChecked
            if (SinkholeVpnService.isRunning.get()) {
                startService(
                    Intent(this, SinkholeVpnService::class.java)
                        .setAction(SinkholeVpnService.ACTION_REFRESH_NOTIFICATION)
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        startPeriodicRefresh()
    }

    override fun onPause() {
        super.onPause()
        refreshRunnable?.let { mainHandler.removeCallbacks(it) }
    }

    override fun onDestroy() {
        super.onDestroy()
        backgroundExecutor.shutdown()
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun requestEnableProtection() {
        val consentIntent = VpnService.prepare(this)
        if (consentIntent != null) {
            vpnPrepareLauncher.launch(consentIntent)
        } else {
            startProtection()
        }
    }

    private fun startProtection() {
        val intent = Intent(this, SinkholeVpnService::class.java).setAction(SinkholeVpnService.ACTION_START)
        ContextCompat.startForegroundService(this, intent)
    }

    private fun stopProtection() {
        val intent = Intent(this, SinkholeVpnService::class.java).setAction(SinkholeVpnService.ACTION_STOP)
        startService(intent)
    }

    private fun updateBlocklist() {
        binding.updateBlocklistButton.isEnabled = false
        binding.blocklistUpdatedText.text = getString(R.string.update_in_progress)
        backgroundExecutor.execute {
            val count = blocklistManager.updateFromUrl(prefs.blocklistUrl)
            mainHandler.post {
                binding.updateBlocklistButton.isEnabled = true
                if (count != null) {
                    Toast.makeText(this, getString(R.string.update_success_format, count), Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, R.string.update_failure, Toast.LENGTH_LONG).show()
                }
                refreshUi()
            }
        }
    }

    private fun startPeriodicRefresh() {
        val runnable = object : Runnable {
            override fun run() {
                refreshUi()
                mainHandler.postDelayed(this, REFRESH_INTERVAL_MS)
            }
        }
        refreshRunnable = runnable
        mainHandler.post(runnable)
    }

    private fun refreshUi() {
        val running = SinkholeVpnService.isRunning.get()
        binding.protectionSwitch.setOnCheckedChangeListener(null)
        binding.protectionSwitch.isChecked = running
        binding.protectionSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) requestEnableProtection() else stopProtection()
        }

        binding.statusText.text = getString(if (running) R.string.status_active else R.string.status_inactive)
        binding.statusSubtitle.text =
            getString(if (running) R.string.status_subtitle_active else R.string.status_subtitle_inactive)
        binding.shieldIcon.setImageResource(if (running) R.drawable.ic_shield_on else R.drawable.ic_shield_off)
        binding.shieldIcon.imageTintList = android.content.res.ColorStateList.valueOf(
            ContextCompat.getColor(this, if (running) R.color.sinkhole_accent else R.color.sinkhole_off)
        )

        binding.statsText.text = getString(R.string.stats_format, prefs.blockedQueryCount, prefs.totalQueryCount)
        binding.blocklistText.text = getString(R.string.blocklist_format, blocklistManager.blockedDomainCount())

        val lastUpdate = prefs.lastBlocklistUpdateMillis
        binding.blocklistUpdatedText.text = if (lastUpdate == 0L) {
            getString(R.string.blocklist_never_updated)
        } else {
            val formatted = DateFormat.getMediumDateFormat(this).format(Date(lastUpdate))
            getString(R.string.blocklist_updated_format, formatted)
        }

        binding.privateDnsWarning.visibility = if (running && isPrivateDnsEnabled()) {
            android.view.View.VISIBLE
        } else {
            android.view.View.GONE
        }
    }

    /**
     * True if system-wide Private DNS (DNS-over-TLS) is on. When it is, the
     * OS may try to validate/use DoT against whatever DNS server the active
     * network reports — including our plain-UDP fake resolver — which can
     * fail and break DNS resolution device-wide (DNS_PROBE_FINISHED_BAD_CONFIG
     * in Chrome) while this VPN is active. Available since Android 9 (API 28);
     * treated as off on older versions where the feature doesn't exist.
     */
    private fun isPrivateDnsEnabled(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return false
        val mode = Settings.Global.getString(contentResolver, "private_dns_mode")
        return mode != null && mode != "off"
    }

    private fun openNetworkSettings() {
        val intent = Intent(Settings.ACTION_WIRELESS_SETTINGS)
        try {
            startActivity(intent)
        } catch (e: ActivityNotFoundException) {
            Toast.makeText(this, R.string.private_dns_warning_title, Toast.LENGTH_SHORT).show()
        }
    }

    companion object {
        private const val REFRESH_INTERVAL_MS = 1000L
    }
}
