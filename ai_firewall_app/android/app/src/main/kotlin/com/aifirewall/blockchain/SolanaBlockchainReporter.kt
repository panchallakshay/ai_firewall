package com.aifirewall.blockchain

import android.content.Context
import android.util.Log
import com.solana.core.Account
import com.solana.core.PublicKey
import com.solana.core.Transaction
import com.solana.networking.RPCEndpoint
import com.solana.rxsolana.api.RxSolanaApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Solana Blockchain Reporter
 * Reports malicious IPs to Solana blockchain for decentralized threat intelligence
 */
class SolanaBlockchainReporter(private val context: Context) {
    
    private val solana = RxSolanaApi(RPCEndpoint.devnetSolana)  // Use devnet for testing
    private val programId = PublicKey("FiReWa11ThreatReg1stryPr0gramID11111111111")
    private val wallet: Account by lazy { loadOrCreateWallet() }
    
    data class ThreatReport(
        val ipAddress: String,
        val threatType: String,
        val confidence: Float,
        val metadata: Map<String, Any>
    )
    
    data class BlockchainThreatInfo(
        val ipAddress: String,
        val threatType: String,
        val confidence: Int,
        val reportCount: Int,
        val status: String,
        val firstSeen: Long,
        val lastConfirmed: Long
    )
    
    /**
     * Report a threat to the blockchain
     */
    fun reportThreat(threat: ThreatReport) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                Log.i(TAG, "Reporting threat to blockchain: ${threat.ipAddress}")
                
                // Create metadata JSON
                val metadata = JSONObject(threat.metadata).toString()
                
                // Build transaction
                val transaction = buildReportTransaction(
                    ipAddress = threat.ipAddress,
                    threatType = threat.threatType,
                    confidence = (threat.confidence * 100).toInt().toByte(),
                    metadata = metadata
                )
                
                // Sign and send
                val signature = solana.sendTransaction(transaction, wallet)
                
                Log.i(TAG, "Threat reported successfully! Signature: $signature")
                
                // Store signature locally for tracking
                storeReportSignature(threat.ipAddress, signature)
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to report threat: ${e.message}", e)
                // Queue for retry
                queueForRetry(threat)
            }
        }
    }
    
    /**
     * Confirm an existing threat report
     */
    fun confirmThreat(ipAddress: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                Log.i(TAG, "Confirming threat: $ipAddress")
                
                val transaction = buildConfirmTransaction(ipAddress)
                val signature = solana.sendTransaction(transaction, wallet)
                
                Log.i(TAG, "Threat confirmed! Signature: $signature")
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to confirm threat: ${e.message}", e)
            }
        }
    }
    
    /**
     * Query threat information from blockchain
     */
    suspend fun queryThreat(ipAddress: String): BlockchainThreatInfo? {
        return try {
            Log.i(TAG, "Querying threat from blockchain: $ipAddress")
            
            // Find PDA (Program Derived Address) for this IP
            val (threatPDA, _) = PublicKey.findProgramAddress(
                listOf("threat".toByteArray(), ipAddress.toByteArray()),
                programId
            )
            
            // Get account data
            val accountInfo = solana.getAccountInfo(threatPDA)
            
            if (accountInfo != null) {
                // Parse account data
                parseThreatData(accountInfo.data)
            } else {
                null
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to query threat: ${e.message}", e)
            null
        }
    }
    
    /**
     * Sync latest threats from blockchain
     */
    suspend fun syncThreats(): List<BlockchainThreatInfo> {
        return try {
            Log.i(TAG, "Syncing threats from blockchain...")
            
            // Get all threat accounts
            val accounts = solana.getProgramAccounts(programId)
            
            val threats = mutableListOf<BlockchainThreatInfo>()
            
            for (account in accounts) {
                val threat = parseThreatData(account.data)
                
                // Only include confirmed threats
                if (threat.status == "Confirmed") {
                    threats.add(threat)
                }
            }
            
            Log.i(TAG, "Synced ${threats.size} threats from blockchain")
            
            // Update local blocklist
            updateLocalBlocklist(threats)
            
            threats
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to sync threats: ${e.message}", e)
            emptyList()
        }
    }
    
    private fun buildReportTransaction(
        ipAddress: String,
        threatType: String,
        confidence: Byte,
        metadata: String
    ): Transaction {
        // Build Anchor instruction for report_threat
        val instruction = buildAnchorInstruction(
            method = "report_threat",
            args = mapOf(
                "ip_address" to ipAddress,
                "threat_type" to threatType,
                "confidence" to confidence,
                "metadata" to metadata
            )
        )
        
        return Transaction().add(instruction)
    }
    
    private fun buildConfirmTransaction(ipAddress: String): Transaction {
        // Build Anchor instruction for confirm_threat
        val instruction = buildAnchorInstruction(
            method = "confirm_threat",
            args = mapOf("ip_address" to ipAddress)
        )
        
        return Transaction().add(instruction)
    }
    
    private fun buildAnchorInstruction(
        method: String,
        args: Map<String, Any>
    ): TransactionInstruction {
        // Simplified - in production, use Anchor client library
        // This would properly encode the instruction data according to Anchor IDL
        
        val data = encodeAnchorData(method, args)
        
        return TransactionInstruction(
            programId = programId,
            keys = getAccountMetas(method, args),
            data = data
        )
    }
    
    private fun encodeAnchorData(method: String, args: Map<String, Any>): ByteArray {
        // Simplified encoding - in production, use Anchor's Borsh serialization
        // Format: [method_discriminator (8 bytes)] + [serialized_args]
        
        val methodHash = hashMethod(method)
        val serializedArgs = serializeArgs(args)
        
        return methodHash + serializedArgs
    }
    
    private fun hashMethod(method: String): ByteArray {
        // Anchor uses first 8 bytes of SHA256("global:method_name")
        val input = "global:$method"
        val hash = java.security.MessageDigest.getInstance("SHA-256")
            .digest(input.toByteArray())
        return hash.copyOf(8)
    }
    
    private fun serializeArgs(args: Map<String, Any>): ByteArray {
        // Simplified Borsh serialization
        // In production, use proper Borsh library
        val buffer = mutableListOf<Byte>()
        
        for ((key, value) in args) {
            when (value) {
                is String -> {
                    val bytes = value.toByteArray()
                    buffer.addAll(intToBytes(bytes.size))
                    buffer.addAll(bytes.toList())
                }
                is Byte -> buffer.add(value)
                is Int -> buffer.addAll(intToBytes(value))
            }
        }
        
        return buffer.toByteArray()
    }
    
    private fun intToBytes(value: Int): List<Byte> {
        return listOf(
            (value and 0xFF).toByte(),
            ((value shr 8) and 0xFF).toByte(),
            ((value shr 16) and 0xFF).toByte(),
            ((value shr 24) and 0xFF).toByte()
        )
    }
    
    private fun getAccountMetas(method: String, args: Map<String, Any>): List<AccountMeta> {
        // Define account metas based on method
        return when (method) {
            "report_threat" -> {
                val ipAddress = args["ip_address"] as String
                val (threatPDA, _) = PublicKey.findProgramAddress(
                    listOf("threat".toByteArray(), ipAddress.toByteArray()),
                    programId
                )
                
                listOf(
                    AccountMeta(threatPDA, isSigner = false, isWritable = true),
                    AccountMeta(wallet.publicKey, isSigner = true, isWritable = true),
                    AccountMeta(PublicKey("11111111111111111111111111111111"), isSigner = false, isWritable = false) // System program
                )
            }
            "confirm_threat" -> {
                val ipAddress = args["ip_address"] as String
                val (threatPDA, _) = PublicKey.findProgramAddress(
                    listOf("threat".toByteArray(), ipAddress.toByteArray()),
                    programId
                )
                
                listOf(
                    AccountMeta(threatPDA, isSigner = false, isWritable = true),
                    AccountMeta(wallet.publicKey, isSigner = true, isWritable = false)
                )
            }
            else -> emptyList()
        }
    }
    
    private fun parseThreatData(data: ByteArray): BlockchainThreatInfo {
        // Simplified parsing - in production, use proper Borsh deserialization
        // This assumes the account data structure from the Rust program
        
        // Skip discriminator (8 bytes)
        var offset = 8
        
        // Parse IP address (String)
        val ipLength = bytesToInt(data.copyOfRange(offset, offset + 4))
        offset += 4
        val ipAddress = String(data.copyOfRange(offset, offset + ipLength))
        offset += ipLength
        
        // Parse threat type (String)
        val typeLength = bytesToInt(data.copyOfRange(offset, offset + 4))
        offset += 4
        val threatType = String(data.copyOfRange(offset, offset + typeLength))
        offset += typeLength
        
        // Parse confidence (u8)
        val confidence = data[offset].toInt() and 0xFF
        offset += 1
        
        // Skip metadata for now
        // ... (would parse metadata string here)
        
        // Parse timestamps and counts
        // ... (would parse remaining fields)
        
        return BlockchainThreatInfo(
            ipAddress = ipAddress,
            threatType = threatType,
            confidence = confidence,
            reportCount = 0,  // Would parse from data
            status = "Confirmed",  // Would parse from data
            firstSeen = 0,  // Would parse from data
            lastConfirmed = 0  // Would parse from data
        )
    }
    
    private fun bytesToInt(bytes: ByteArray): Int {
        return (bytes[0].toInt() and 0xFF) or
               ((bytes[1].toInt() and 0xFF) shl 8) or
               ((bytes[2].toInt() and 0xFF) shl 16) or
               ((bytes[3].toInt() and 0xFF) shl 24)
    }
    
    private fun loadOrCreateWallet(): Account {
        val prefs = context.getSharedPreferences("solana_wallet", Context.MODE_PRIVATE)
        val privateKeyHex = prefs.getString("private_key", null)
        
        return if (privateKeyHex != null) {
            // Load existing wallet
            val privateKey = hexToBytes(privateKeyHex)
            Account(privateKey)
        } else {
            // Create new wallet
            val newWallet = Account()
            prefs.edit()
                .putString("private_key", bytesToHex(newWallet.secretKey))
                .apply()
            newWallet
        }
    }
    
    private fun storeReportSignature(ipAddress: String, signature: String) {
        val prefs = context.getSharedPreferences("blockchain_reports", Context.MODE_PRIVATE)
        prefs.edit()
            .putString(ipAddress, signature)
            .apply()
    }
    
    private fun queueForRetry(threat: ThreatReport) {
        // Store in local database for retry later
        // Would implement retry queue with exponential backoff
    }
    
    private fun updateLocalBlocklist(threats: List<BlockchainThreatInfo>) {
        // Update local blocklist with blockchain threats
        val prefs = context.getSharedPreferences("blockchain_blocklist", Context.MODE_PRIVATE)
        val editor = prefs.edit()
        
        for (threat in threats) {
            editor.putString(threat.ipAddress, threat.threatType)
        }
        
        editor.apply()
        Log.i(TAG, "Updated local blocklist with ${threats.size} blockchain threats")
    }
    
    private fun hexToBytes(hex: String): ByteArray {
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
    
    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }
    
    companion object {
        private const val TAG = "SolanaBlockchain"
    }
}
