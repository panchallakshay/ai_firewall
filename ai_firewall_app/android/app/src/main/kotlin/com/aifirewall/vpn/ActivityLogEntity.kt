package com.aifirewall.vpn

// Removed Room annotations to avoid complex build dependency configuration
data class ActivityLogEntity(
    val id: Long = 0,
    val timestamp: Long,
    val domain: String,
    val ipAddress: String,
    val port: Int,
    val protocol: String,
    val action: String,
    val reason: String,
    val appName: String,
    val dataUsage: Long
)
