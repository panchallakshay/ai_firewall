package com.aifirewall.ai_firewall_app

import android.content.Intent
import android.net.VpnService
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.EventChannel
import com.aifirewall.vpn.AIFirewallVpnService

/**
 * MainActivity - Bridge between Flutter UI and AI Firewall VPN Service
 * Handles MethodChannel calls from Saksham's UI to control VPN
 */
class MainActivity: FlutterActivity() {
    
    private val CHANNEL = "com.aifirewall/vpn"
    private val EVENT_CHANNEL = "com.aifirewall/events"
    private val VPN_REQUEST_CODE = 1001
    
    private var pendingResult: MethodChannel.Result? = null
    
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        
        // ✅ MethodChannel - Handle UI commands
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "startVpn" -> {
                    startVpnService(result)
                }
                "stopVpn" -> {
                    stopVpnService(result)
                }
                "checkPermission" -> {
                    val hasPermission = checkVpnPermission()
                    result.success(hasPermission)
                }
                "setPolicyMode" -> {
                    val mode = call.argument<String>("mode") ?: "balanced"
                    setPolicyMode(mode)
                    result.success(true)
                }
                else -> {
                    result.notImplemented()
                }
            }
        }
        
        // ✅ EventChannel - Stream firewall events to UI
        EventChannel(flutterEngine.dartExecutor.binaryMessenger, EVENT_CHANNEL).setStreamHandler(
            object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                    // TODO: Connect to AIFirewallVpnService event stream
                    // For now, send test events
                    events?.success("ACT:ALLOW|example.com|DNS")
                }
                
                override fun onCancel(arguments: Any?) {
                    // Cleanup when UI stops listening
                }
            }
        )
    }
    
    /**
     * Start VPN Service
     * Requests permission if needed, then starts AIFirewallVpnService
     */
    private fun startVpnService(result: MethodChannel.Result) {
        val intent = VpnService.prepare(this)
        
        if (intent != null) {
            // Permission not granted, request it
            pendingResult = result
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            // Permission already granted, start VPN
            val serviceIntent = Intent(this, AIFirewallVpnService::class.java).apply {
                action = AIFirewallVpnService.ACTION_START
            }
            startService(serviceIntent)
            result.success(true)
        }
    }
    
    /**
     * Stop VPN Service
     */
    private fun stopVpnService(result: MethodChannel.Result) {
        val intent = Intent(this, AIFirewallVpnService::class.java).apply {
            action = AIFirewallVpnService.ACTION_STOP
        }
        startService(intent)
        result.success(true)
    }
    
    /**
     * Check if VPN permission is granted
     */
    private fun checkVpnPermission(): Boolean {
        val intent = VpnService.prepare(this)
        return intent == null
    }
    
    /**
     * Set AI policy mode (strict/balanced)
     */
    private fun setPolicyMode(mode: String) {
        // TODO: Send policy mode to AIFirewallVpnService
        // For now, just log it
        android.util.Log.i("MainActivity", "Policy mode set to: $mode")
    }
    
    /**
     * Handle VPN permission result
     */
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                // Permission granted, start VPN
                val intent = Intent(this, AIFirewallVpnService::class.java).apply {
                    action = AIFirewallVpnService.ACTION_START
                }
                startService(intent)
                pendingResult?.success(true)
            } else {
                // Permission denied
                pendingResult?.success(false)
            }
            pendingResult = null
        }
    }
}
