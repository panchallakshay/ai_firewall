package com.aifirewall.vpn

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.activity.result.ActivityResultLauncher

/**
 * VpnHelper - Helper class for VPN operations
 * 
 * Responsibilities:
 * - Request VPN permission from user
 * - Start/stop VPN service
 * - Check VPN status
 * - Handle VPN lifecycle
 */
class VpnHelper(private val context: Context) {
    
    companion object {
        const val VPN_PERMISSION_REQUEST_CODE = 100
    }
    
    /**
     * Check if VPN permission is granted
     * 
     * @return true if permission granted, false otherwise
     */
    fun isVpnPermissionGranted(): Boolean {
        val intent = VpnService.prepare(context)
        return intent == null
    }
    
    /**
     * Request VPN permission from user
     * Shows system dialog asking user to allow VPN
     * 
     * @param activity Activity to launch permission request from
     * @return Intent to launch for permission request, or null if already granted
     */
    fun requestVpnPermission(activity: Activity): Intent? {
        return VpnService.prepare(context)
    }
    
    /**
     * Start VPN service
     * 
     * @return true if service started successfully, false otherwise
     */
    fun startVpn(): Boolean {
        return try {
            val intent = Intent(context, FirewallVpnService::class.java)
            context.startService(intent)
            true
        } catch (e: Exception) {
            android.util.Log.e("VpnHelper", "Failed to start VPN", e)
            false
        }
    }
    
    /**
     * Stop VPN service
     * 
     * @return true if service stopped successfully, false otherwise
     */
    fun stopVpn(): Boolean {
        return try {
            val intent = Intent(context, FirewallVpnService::class.java)
            intent.action = "STOP_VPN"
            context.startService(intent)
            true
        } catch (e: Exception) {
            android.util.Log.e("VpnHelper", "Failed to stop VPN", e)
            false
        }
    }
    
    /**
     * Toggle VPN on/off
     * 
     * @param activity Activity to launch permission request from (if needed)
     * @return true if VPN was toggled, false if permission needed
     */
    fun toggleVpn(activity: Activity): Boolean {
        // Check if VPN is already running
        // TODO: Implement proper VPN status check
        
        // Check permission
        if (!isVpnPermissionGranted()) {
            val permissionIntent = requestVpnPermission(activity)
            if (permissionIntent != null) {
                activity.startActivityForResult(permissionIntent, VPN_PERMISSION_REQUEST_CODE)
                return false
            }
        }
        
        // Toggle VPN
        // TODO: Check actual VPN status and toggle accordingly
        return startVpn()
    }
}
