package com.aifirewall

import android.content.Intent
import android.os.Bundle
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import com.aifirewall.vpn.VpnHelper

/**
 * MainActivity - Flutter activity with method channel for VPN control
 * 
 * Method Channel: "com.aifirewall/vpn"
 * 
 * Methods:
 * - startVpn(): Start VPN service
 * - stopVpn(): Stop VPN service
 * - checkPermission(): Check if VPN permission is granted
 * - getStats(): Get firewall statistics
 */
class MainActivity: FlutterActivity() {
    
    private lateinit var vpnHelper: VpnHelper
    private val CHANNEL = "com.aifirewall/vpn"
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        vpnHelper = VpnHelper(this)
    }
    
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "startVpn" -> {
                        handleStartVpn(result)
                    }
                    "stopVpn" -> {
                        handleStopVpn(result)
                    }
                    "checkPermission" -> {
                        handleCheckPermission(result)
                    }
                    "getStats" -> {
                        handleGetStats(result)
                    }
                    "setPolicyMode" -> {
                        val mode = call.argument<String>("mode")
                        handleSetPolicyMode(mode, result)
                    }
                    "resetStrikes" -> {
                        val flowKey = call.argument<String>("flowKey")
                        handleResetStrikes(flowKey, result)
                    }
                    else -> {
                        result.notImplemented()
                    }
                }
            }
    }
    
    /**
     * Start VPN service
     */
    private fun handleStartVpn(result: MethodChannel.Result) {
        try {
            // Check permission first
            if (!vpnHelper.isVpnPermissionGranted()) {
                val permissionIntent = vpnHelper.requestVpnPermission(this)
                if (permissionIntent != null) {
                    startActivityForResult(permissionIntent, VpnHelper.VPN_PERMISSION_REQUEST_CODE)
                    result.success(mapOf(
                        "success" to false,
                        "needsPermission" to true,
                        "message" to "VPN permission required"
                    ))
                    return
                }
            }
            
            // Start VPN
            val started = vpnHelper.startVpn()
            result.success(mapOf(
                "success" to started,
                "needsPermission" to false,
                "message" to if (started) "VPN started" else "Failed to start VPN"
            ))
            
        } catch (e: Exception) {
            result.error("VPN_ERROR", "Failed to start VPN: ${e.message}", null)
        }
    }
    
    /**
     * Stop VPN service
     */
    private fun handleStopVpn(result: MethodChannel.Result) {
        try {
            val stopped = vpnHelper.stopVpn()
            result.success(mapOf(
                "success" to stopped,
                "message" to if (stopped) "VPN stopped" else "Failed to stop VPN"
            ))
        } catch (e: Exception) {
            result.error("VPN_ERROR", "Failed to stop VPN: ${e.message}", null)
        }
    }
    
    /**
     * Check VPN permission
     */
    private fun handleCheckPermission(result: MethodChannel.Result) {
        try {
            val granted = vpnHelper.isVpnPermissionGranted()
            result.success(mapOf(
                "granted" to granted
            ))
        } catch (e: Exception) {
            result.error("PERMISSION_ERROR", "Failed to check permission: ${e.message}", null)
        }
    }
    
    /**
     * Get firewall statistics
     * TODO: Implement statistics tracking in VPN service
     */
    private fun handleGetStats(result: MethodChannel.Result) {
        try {
            // TODO: Get actual stats from VPN service
            result.success(mapOf(
                "packetsProcessed" to 0,
                "packetsAllowed" to 0,
                "packetsBlocked" to 0,
                "threatsBlocked" to 0
            ))
        } catch (e: Exception) {
            result.error("STATS_ERROR", "Failed to get stats: ${e.message}", null)
        }
    }
    
    /**
     * Set policy mode (STRICT, BALANCED, PERMISSIVE)
     */
    private fun handleSetPolicyMode(mode: String?, result: MethodChannel.Result) {
        try {
            if (mode == null) {
                result.error("INVALID_ARGUMENT", "Mode cannot be null", null)
                return
            }
            
            // TODO: Send mode to VPN service
            result.success(mapOf(
                "success" to true,
                "mode" to mode
            ))
        } catch (e: Exception) {
            result.error("POLICY_ERROR", "Failed to set policy mode: ${e.message}", null)
        }
    }
    
    /**
     * Reset strikes for a flow (user override)
     */
    private fun handleResetStrikes(flowKey: String?, result: MethodChannel.Result) {
        try {
            if (flowKey == null) {
                result.error("INVALID_ARGUMENT", "Flow key cannot be null", null)
                return
            }
            
            // TODO: Send reset command to VPN service
            result.success(mapOf(
                "success" to true,
                "flowKey" to flowKey
            ))
        } catch (e: Exception) {
            result.error("RESET_ERROR", "Failed to reset strikes: ${e.message}", null)
        }
    }
    
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        
        if (requestCode == VpnHelper.VPN_PERMISSION_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                // Permission granted, start VPN
                vpnHelper.startVpn()
            }
        }
    }
}
