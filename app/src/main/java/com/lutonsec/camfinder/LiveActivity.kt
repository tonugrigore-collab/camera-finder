package com.lutonsec.camfinder

import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.TextView
import androidx.annotation.OptIn
import androidx.appcompat.app.AppCompatActivity
import androidx.media3.common.MediaItem
import androidx.media3.common.PlaybackException
import androidx.media3.common.Player
import androidx.media3.common.util.UnstableApi
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.exoplayer.rtsp.RtspMediaSource
import androidx.media3.ui.PlayerView

/**
 * Live view via ExoPlayer's native RTSP — smooth H.264/H.265 straight from the camera, no plug-in, no ffmpeg.
 * Main/Sub toggle, fullscreen, and it cycles through candidate RTSP URLs until one plays.
 */
@OptIn(UnstableApi::class)
class LiveActivity : AppCompatActivity() {

    private lateinit var playerView: PlayerView
    private lateinit var statusLabel: TextView
    private lateinit var streamButton: Button
    private var player: ExoPlayer? = null

    private var ip = ""
    private var brand = ""
    private var user = ""
    private var pass = ""
    private var useSub = true
    private var candidates: List<String> = emptyList()
    private var idx = 0
    private var full = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        setContentView(R.layout.activity_live)
        playerView = findViewById(R.id.playerView)
        statusLabel = findViewById(R.id.liveStatus)
        streamButton = findViewById(R.id.streamButton)

        ip = intent.getStringExtra("ip") ?: ""
        brand = intent.getStringExtra("brand") ?: ""
        user = intent.getStringExtra("user") ?: ""
        pass = intent.getStringExtra("pass") ?: ""
        title = "Live — $ip"

        streamButton.text = "Sub stream"
        streamButton.setOnClickListener {
            useSub = !useSub
            streamButton.text = if (useSub) "Sub stream" else "Main stream"
            start()
        }
        findViewById<Button>(R.id.fullButton).setOnClickListener { toggleFull() }
        playerView.setOnClickListener { toggleFull() }
        start()
    }

    private fun start() {
        candidates = Rtsp.urls(ip, brand, user, pass, useSub)
        idx = 0
        statusLabel.text = "Connecting (" + (if (useSub) "sub" else "main") + ")…"
        play()
    }

    private fun play() {
        if (isFinishing || isDestroyed) return
        release()
        if (idx >= candidates.size) {
            statusLabel.text = "Couldn't play the live stream. Check the password, or use Open in browser."
            return
        }
        val p = ExoPlayer.Builder(this).build()
        val source = RtspMediaSource.Factory()
            .setForceUseRtpTcp(true)
            .createMediaSource(MediaItem.fromUri(candidates[idx]))
        p.setMediaSource(source)
        p.addListener(object : Player.Listener {
            override fun onPlayerError(error: PlaybackException) {
                idx++
                playerView.post { play() }     // try the next candidate URL
            }
            override fun onPlaybackStateChanged(state: Int) {
                if (state == Player.STATE_READY) statusLabel.text = if (useSub) "Sub stream" else "Main stream"
            }
        })
        p.playWhenReady = true
        p.prepare()
        playerView.player = p
        player = p
    }

    private fun release() {
        player?.let { playerView.player = null; it.release() }
        player = null
    }

    private fun toggleFull() {
        full = !full
        findViewById<View>(R.id.liveBar).visibility = if (full) View.GONE else View.VISIBLE
        @Suppress("DEPRECATION")
        window.decorView.systemUiVisibility = if (full)
            (View.SYSTEM_UI_FLAG_FULLSCREEN or View.SYSTEM_UI_FLAG_HIDE_NAVIGATION or
             View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY or View.SYSTEM_UI_FLAG_LAYOUT_STABLE or
             View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION)
        else View.SYSTEM_UI_FLAG_VISIBLE
    }

    override fun onStop() { super.onStop(); release() }
    override fun onDestroy() { super.onDestroy(); release() }
}
