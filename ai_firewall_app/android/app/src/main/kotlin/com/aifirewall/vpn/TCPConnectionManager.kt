package com.aifirewall.vpn

import android.util.Log
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*

/**
 * TCP Connection Manager
 * Manages lifecycle of TCP connections and cleanup
 */
class TCPConnectionManager {
    
    private val connections = ConcurrentHashMap<FlowKey, TCPConnection>()
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val cleanupExecutor = Executors.newSingleThreadScheduledExecutor()
    
    companion object {
        private const val TAG = "TCPConnectionManager"
        private const val MAX_CONNECTIONS = 1000
        private const val IDLE_TIMEOUT_MS = 5 * 60 * 1000L  // 5 minutes
        private const val CLEANUP_INTERVAL_MS = 60 * 1000L   // 1 minute
    }
    
    init {
        // Start periodic cleanup
        cleanupExecutor.scheduleAtFixedRate(
            { cleanupIdleConnections() },
            CLEANUP_INTERVAL_MS,
            CLEANUP_INTERVAL_MS,
            TimeUnit.MILLISECONDS
        )
    }
    
    /**
     * Get or create TCP connection
     */
    fun getOrCreateConnection(
        flowKey: FlowKey,
        onCreate: (FlowKey) -> Socket
    ): TCPConnection? {
        // Check if connection already exists
        connections[flowKey]?.let { existing ->
            if (existing.isActive()) {
                existing.touch()
                return existing
            } else {
                // Remove stale connection
                removeConnection(flowKey)
            }
        }
        
        // Check connection limit
        if (connections.size >= MAX_CONNECTIONS) {
            Log.w(TAG, "Max connections reached ($MAX_CONNECTIONS), cleaning up...")
            cleanupOldestConnections(100)
        }
        
        return try {
            // Create new socket
            val socket = onCreate(flowKey)
            
            // Create connection object
            val connection = TCPConnection(
                flowKey = flowKey,
                socket = socket,
                state = TCPState.ESTABLISHED
            )
            
            connections[flowKey] = connection
            
            Log.d(TAG, "Created TCP connection: $flowKey (total: ${connections.size})")
            connection
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create connection for $flowKey", e)
            null
        }
    }
    
    /**
     * Get existing connection
     */
    fun getConnection(flowKey: FlowKey): TCPConnection? {
        return connections[flowKey]?.takeIf { it.isActive() }
    }
    
    /**
     * Remove connection
     */
    fun removeConnection(flowKey: FlowKey) {
        connections.remove(flowKey)?.let { connection ->
            connection.close()
            Log.d(TAG, "Removed TCP connection: $flowKey (total: ${connections.size})")
        }
    }
    
    /**
     * Update connection state
     */
    fun updateState(flowKey: FlowKey, newState: TCPState) {
        connections[flowKey]?.let { connection ->
            connection.state = newState
            connection.touch()
            
            // Auto-close if in terminal state
            if (newState == TCPState.CLOSED) {
                removeConnection(flowKey)
            }
        }
    }
    
    /**
     * Record bytes sent
     */
    fun recordBytesSent(flowKey: FlowKey, bytes: Int) {
        connections[flowKey]?.let { connection ->
            connection.bytesSent.addAndGet(bytes.toLong())
            connection.packetsForwarded.incrementAndGet()
            connection.touch()
        }
    }
    
    /**
     * Record bytes received
     */
    fun recordBytesReceived(flowKey: FlowKey, bytes: Int) {
        connections[flowKey]?.let { connection ->
            connection.bytesReceived.addAndGet(bytes.toLong())
            connection.touch()
        }
    }
    
    /**
     * Cleanup idle connections
     */
    private fun cleanupIdleConnections() {
        scope.launch {
            val now = System.currentTimeMillis()
            val toRemove = mutableListOf<FlowKey>()
            
            connections.forEach { (key, connection) ->
                if (connection.isIdle(IDLE_TIMEOUT_MS) || !connection.isActive()) {
                    toRemove.add(key)
                }
            }
            
            toRemove.forEach { key ->
                removeConnection(key)
            }
            
            if (toRemove.isNotEmpty()) {
                Log.d(TAG, "Cleaned up ${toRemove.size} idle connections (remaining: ${connections.size})")
            }
        }
    }
    
    /**
     * Cleanup oldest connections when limit reached
     */
    private fun cleanupOldestConnections(count: Int) {
        val sorted = connections.entries.sortedBy { it.value.lastActivity }
        sorted.take(count).forEach { (key, _) ->
            removeConnection(key)
        }
    }
    
    /**
     * Get connection statistics
     */
    fun getStats(): Map<String, Any> {
        val totalBytesSent = connections.values.sumOf { it.bytesSent.get() }
        val totalBytesReceived = connections.values.sumOf { it.bytesReceived.get() }
        val totalPackets = connections.values.sumOf { it.packetsForwarded.get() }
        
        return mapOf(
            "total_connections" to connections.size,
            "established" to connections.values.count { it.state == TCPState.ESTABLISHED },
            "bytes_sent" to totalBytesSent,
            "bytes_received" to totalBytesReceived,
            "packets_forwarded" to totalPackets
        )
    }
    
    /**
     * Shutdown and cleanup all connections
     */
    fun shutdown() {
        Log.i(TAG, "Shutting down TCP connection manager...")
        
        // Stop cleanup task
        cleanupExecutor.shutdown()
        
        // Close all connections
        connections.keys.toList().forEach { key ->
            removeConnection(key)
        }
        
        // Cancel coroutines
        scope.cancel()
        
        Log.i(TAG, "TCP connection manager shutdown complete")
    }
}
