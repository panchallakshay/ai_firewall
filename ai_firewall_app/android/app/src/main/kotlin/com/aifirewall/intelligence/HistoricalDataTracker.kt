package com.aifirewall.intelligence

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * Historical Data Tracker
 * Tracks previous attacks from same IPs/domains for pattern analysis
 */
class HistoricalDataTracker(context: Context) : SQLiteOpenHelper(
    context, DATABASE_NAME, null, DATABASE_VERSION
) {
    
    data class HistoricalInfo(
        val previousBlocksFromIP: Int,
        val previousBlocksFromDomain: Int,
        val firstSeenTimestamp: Long,
        val lastSeenTimestamp: Long,
        val totalAttempts: Int,
        val blockedCount: Int,
        val allowedCount: Int,
        val attackTypes: List<String>,
        val averageConfidence: Float
    )
    
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE ip_history (
                ip_address TEXT PRIMARY KEY,
                first_seen INTEGER,
                last_seen INTEGER,
                total_attempts INTEGER,
                blocked_count INTEGER,
                allowed_count INTEGER,
                attack_types TEXT,
                avg_confidence REAL
            )
        """)
        
        db.execSQL("""
            CREATE TABLE domain_history (
                domain TEXT PRIMARY KEY,
                first_seen INTEGER,
                last_seen INTEGER,
                total_attempts INTEGER,
                blocked_count INTEGER,
                allowed_count INTEGER,
                attack_types TEXT,
                avg_confidence REAL
            )
        """)
        
        db.execSQL("""
            CREATE INDEX idx_ip_last_seen ON ip_history(last_seen)
        """)
        
        db.execSQL("""
            CREATE INDEX idx_domain_last_seen ON domain_history(last_seen)
        """)
    }
    
    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS ip_history")
        db.execSQL("DROP TABLE IF EXISTS domain_history")
        onCreate(db)
    }
    
    fun recordAttempt(
        ipAddress: String,
        domain: String,
        wasBlocked: Boolean,
        attackType: String,
        confidence: Float
    ) {
        val db = writableDatabase
        val timestamp = System.currentTimeMillis()
        
        // Update IP history
        updateHistory(
            db, "ip_history", "ip_address", ipAddress,
            timestamp, wasBlocked, attackType, confidence
        )
        
        // Update domain history
        updateHistory(
            db, "domain_history", "domain", domain,
            timestamp, wasBlocked, attackType, confidence
        )
    }
    
    private fun updateHistory(
        db: SQLiteDatabase,
        table: String,
        keyColumn: String,
        keyValue: String,
        timestamp: Long,
        wasBlocked: Boolean,
        attackType: String,
        confidence: Float
    ) {
        val cursor = db.query(
            table,
            null,
            "$keyColumn = ?",
            arrayOf(keyValue),
            null, null, null
        )
        
        if (cursor.moveToFirst()) {
            // Update existing record
            val totalAttempts = cursor.getInt(cursor.getColumnIndexOrThrow("total_attempts")) + 1
            val blockedCount = cursor.getInt(cursor.getColumnIndexOrThrow("blocked_count")) +
                    if (wasBlocked) 1 else 0
            val allowedCount = cursor.getInt(cursor.getColumnIndexOrThrow("allowed_count")) +
                    if (!wasBlocked) 1 else 0
            val existingTypes = cursor.getString(cursor.getColumnIndexOrThrow("attack_types"))
            val newTypes = if (attackType !in existingTypes) {
                "$existingTypes,$attackType"
            } else {
                existingTypes
            }
            val avgConfidence = cursor.getFloat(cursor.getColumnIndexOrThrow("avg_confidence"))
            val newAvgConfidence = (avgConfidence * (totalAttempts - 1) + confidence) / totalAttempts
            
            db.execSQL("""
                UPDATE $table SET
                    last_seen = $timestamp,
                    total_attempts = $totalAttempts,
                    blocked_count = $blockedCount,
                    allowed_count = $allowedCount,
                    attack_types = '$newTypes',
                    avg_confidence = $newAvgConfidence
                WHERE $keyColumn = '$keyValue'
            """)
        } else {
            // Insert new record
            db.execSQL("""
                INSERT INTO $table VALUES (
                    '$keyValue',
                    $timestamp,
                    $timestamp,
                    1,
                    ${if (wasBlocked) 1 else 0},
                    ${if (!wasBlocked) 1 else 0},
                    '$attackType',
                    $confidence
                )
            """)
        }
        cursor.close()
    }
    
    fun getIPHistory(ipAddress: String): HistoricalInfo? {
        return getHistory("ip_history", "ip_address", ipAddress)
    }
    
    fun getDomainHistory(domain: String): HistoricalInfo? {
        return getHistory("domain_history", "domain", domain)
    }
    
    private fun getHistory(table: String, keyColumn: String, keyValue: String): HistoricalInfo? {
        val db = readableDatabase
        val cursor = db.query(
            table,
            null,
            "$keyColumn = ?",
            arrayOf(keyValue),
            null, null, null
        )
        
        return if (cursor.moveToFirst()) {
            val info = HistoricalInfo(
                previousBlocksFromIP = if (table == "ip_history") 
                    cursor.getInt(cursor.getColumnIndexOrThrow("blocked_count")) else 0,
                previousBlocksFromDomain = if (table == "domain_history")
                    cursor.getInt(cursor.getColumnIndexOrThrow("blocked_count")) else 0,
                firstSeenTimestamp = cursor.getLong(cursor.getColumnIndexOrThrow("first_seen")),
                lastSeenTimestamp = cursor.getLong(cursor.getColumnIndexOrThrow("last_seen")),
                totalAttempts = cursor.getInt(cursor.getColumnIndexOrThrow("total_attempts")),
                blockedCount = cursor.getInt(cursor.getColumnIndexOrThrow("blocked_count")),
                allowedCount = cursor.getInt(cursor.getColumnIndexOrThrow("allowed_count")),
                attackTypes = cursor.getString(cursor.getColumnIndexOrThrow("attack_types")).split(","),
                averageConfidence = cursor.getFloat(cursor.getColumnIndexOrThrow("avg_confidence"))
            )
            cursor.close()
            info
        } else {
            cursor.close()
            null
        }
    }
    
    // Clean old records (older than 30 days)
    fun cleanOldRecords() {
        val db = writableDatabase
        val thirtyDaysAgo = System.currentTimeMillis() - (30 * 24 * 60 * 60 * 1000)
        
        db.execSQL("DELETE FROM ip_history WHERE last_seen < $thirtyDaysAgo")
        db.execSQL("DELETE FROM domain_history WHERE last_seen < $thirtyDaysAgo")
    }
    
    companion object {
        private const val DATABASE_NAME = "historical_data.db"
        private const val DATABASE_VERSION = 1
    }
}
