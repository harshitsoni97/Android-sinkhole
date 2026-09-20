package com.sinkhole.adblock.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.getSystemService
import com.sinkhole.adblock.R
import com.sinkhole.adblock.databinding.ActivityLogViewerBinding
import com.sinkhole.adblock.log.SinkholeLog

/**
 * Lets the user view, copy, or share the app's own log buffer — handy for
 * diagnosing DNS/VPN issues without needing adb/logcat access, which most
 * users don't have.
 */
class LogViewerActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLogViewerBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLogViewerBinding.inflate(layoutInflater)
        setContentView(binding.root)
        title = getString(R.string.log_viewer_title)

        refreshLogText()

        binding.copyLogsButton.setOnClickListener {
            val clipboard = getSystemService<ClipboardManager>()
            clipboard?.setPrimaryClip(ClipData.newPlainText("DNS Sinkhole logs", currentLogText()))
            Toast.makeText(this, R.string.logs_copied, Toast.LENGTH_SHORT).show()
        }

        binding.shareLogsButton.setOnClickListener {
            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_SUBJECT, "DNS Sinkhole logs")
                putExtra(Intent.EXTRA_TEXT, currentLogText())
            }
            startActivity(Intent.createChooser(shareIntent, getString(R.string.action_share_logs)))
        }

        binding.clearLogsButton.setOnClickListener {
            SinkholeLog.clear()
            refreshLogText()
        }
    }

    override fun onResume() {
        super.onResume()
        refreshLogText()
    }

    private fun currentLogText(): String =
        SinkholeLog.getLogText().ifEmpty { getString(R.string.logs_empty) }

    private fun refreshLogText() {
        binding.logText.text = currentLogText()
    }
}
