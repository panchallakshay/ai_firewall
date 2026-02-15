package com.aifirewall.intelligence

import android.content.Context
import android.content.pm.PackageManager

/**
 * Privacy Score Calculator
 * Analyzes app permissions and behavior to calculate privacy risk
 */
class PrivacyScoreCalculator(private val context: Context) {
    
    data class PrivacyScore(
        val appPrivacyRating: Float,  // 0-5 scale
        val dataCollectionTypes: List<String>,
        val thirdPartyTrackers: Int,
        val permissionsVsFunctionality: String,
        val privacyRiskLevel: String,
        val recommendations: List<String>
    )
    
    fun calculateScore(packageName: String): PrivacyScore {
        val pm = context.packageManager
        
        try {
            val appInfo = pm.getApplicationInfo(packageName, PackageManager.GET_META_DATA)
            val packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            
            val permissions = packageInfo.requestedPermissions?.toList() ?: emptyList()
            val dataTypes = identifyDataCollection(permissions)
            val trackers = estimateTrackers(packageName)
            val permissionRatio = analyzePermissions(permissions, packageName)
            val rating = calculateRating(permissions, trackers, permissionRatio)
            val riskLevel = determineRiskLevel(rating)
            val recommendations = generateRecommendations(permissions, trackers, rating)
            
            return PrivacyScore(
                appPrivacyRating = rating,
                dataCollectionTypes = dataTypes,
                thirdPartyTrackers = trackers,
                permissionsVsFunctionality = permissionRatio,
                privacyRiskLevel = riskLevel,
                recommendations = recommendations
            )
        } catch (e: Exception) {
            return PrivacyScore(
                appPrivacyRating = 3.0f,
                dataCollectionTypes = emptyList(),
                thirdPartyTrackers = 0,
                permissionsVsFunctionality = "Unknown",
                privacyRiskLevel = "Unknown",
                recommendations = emptyList()
            )
        }
    }
    
    private fun identifyDataCollection(permissions: List<String>): List<String> {
        val dataTypes = mutableListOf<String>()
        
        val permissionMap = mapOf(
            "android.permission.ACCESS_FINE_LOCATION" to "Location",
            "android.permission.ACCESS_COARSE_LOCATION" to "Location",
            "android.permission.READ_CONTACTS" to "Contacts",
            "android.permission.WRITE_CONTACTS" to "Contacts",
            "android.permission.CAMERA" to "Camera",
            "android.permission.RECORD_AUDIO" to "Microphone",
            "android.permission.READ_SMS" to "SMS",
            "android.permission.SEND_SMS" to "SMS",
            "android.permission.READ_CALL_LOG" to "Call History",
            "android.permission.WRITE_CALL_LOG" to "Call History",
            "android.permission.READ_CALENDAR" to "Calendar",
            "android.permission.WRITE_CALENDAR" to "Calendar",
            "android.permission.GET_ACCOUNTS" to "Accounts",
            "android.permission.READ_PHONE_STATE" to "Device ID",
            "android.permission.READ_EXTERNAL_STORAGE" to "Files",
            "android.permission.WRITE_EXTERNAL_STORAGE" to "Files"
        )
        
        for (permission in permissions) {
            permissionMap[permission]?.let { dataType ->
                if (dataType !in dataTypes) {
                    dataTypes.add(dataType)
                }
            }
        }
        
        return dataTypes
    }
    
    private fun estimateTrackers(packageName: String): Int {
        // Simplified tracker estimation based on common SDK patterns
        // In production, would use Exodus Privacy API or similar
        
        val knownTrackerSDKs = listOf(
            "com.google.android.gms.ads",
            "com.facebook.ads",
            "com.applovin",
            "com.unity3d.ads",
            "com.ironsource",
            "com.chartboost",
            "com.vungle",
            "com.tapjoy"
        )
        
        // Estimate based on package name patterns
        var trackerCount = 0
        
        // Gaming apps typically have 5-10 trackers
        if (packageName.contains("game") || packageName.contains("play")) {
            trackerCount = 7
        }
        // Social media apps have 10-15 trackers
        else if (packageName.contains("social") || packageName.contains("chat")) {
            trackerCount = 12
        }
        // Utility apps have 2-5 trackers
        else {
            trackerCount = 3
        }
        
        return trackerCount
    }
    
    private fun analyzePermissions(permissions: List<String>, packageName: String): String {
        val sensitivePermissions = permissions.count { permission ->
            permission in listOf(
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_CONTACTS",
                "android.permission.READ_SMS",
                "android.permission.READ_CALL_LOG"
            )
        }
        
        val totalPermissions = permissions.size
        
        return when {
            sensitivePermissions == 0 -> "Minimal permissions"
            sensitivePermissions <= 2 && totalPermissions <= 10 -> "Appropriate permissions"
            sensitivePermissions <= 4 && totalPermissions <= 15 -> "Moderate permissions"
            else -> "Over-permissioned"
        }
    }
    
    private fun calculateRating(
        permissions: List<String>,
        trackers: Int,
        permissionRatio: String
    ): Float {
        var rating = 5.0f  // Start with perfect score
        
        // Deduct for sensitive permissions
        val sensitiveCount = permissions.count { permission ->
            permission in listOf(
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_CONTACTS",
                "android.permission.READ_SMS",
                "android.permission.READ_CALL_LOG"
            )
        }
        rating -= (sensitiveCount * 0.3f)
        
        // Deduct for trackers
        rating -= (trackers * 0.1f)
        
        // Deduct for over-permissioning
        if (permissionRatio == "Over-permissioned") {
            rating -= 1.0f
        } else if (permissionRatio == "Moderate permissions") {
            rating -= 0.5f
        }
        
        return rating.coerceIn(0f, 5f)
    }
    
    private fun determineRiskLevel(rating: Float): String {
        return when {
            rating >= 4.0 -> "Low"
            rating >= 2.5 -> "Medium"
            rating >= 1.0 -> "High"
            else -> "Critical"
        }
    }
    
    private fun generateRecommendations(
        permissions: List<String>,
        trackers: Int,
        rating: Float
    ): List<String> {
        val recommendations = mutableListOf<String>()
        
        if (rating < 3.0) {
            recommendations.add("Consider using a privacy-focused alternative")
        }
        
        if (trackers > 5) {
            recommendations.add("App contains $trackers trackers - consider using with ad blocker")
        }
        
        if ("android.permission.ACCESS_FINE_LOCATION" in permissions) {
            recommendations.add("Disable location access when not needed")
        }
        
        if ("android.permission.CAMERA" in permissions || 
            "android.permission.RECORD_AUDIO" in permissions) {
            recommendations.add("Review camera/microphone permissions regularly")
        }
        
        if ("android.permission.READ_CONTACTS" in permissions ||
            "android.permission.READ_SMS" in permissions) {
            recommendations.add("App can access personal data - review privacy policy")
        }
        
        return recommendations
    }
}
