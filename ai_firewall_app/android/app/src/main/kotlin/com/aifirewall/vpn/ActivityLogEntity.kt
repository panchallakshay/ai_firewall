package com.aifirewall.vpn

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "activity_logs")
data class ActivityLogEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
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
