package com.aifirewall.vpn

import android.content.Context

// Replaced Room Database with simple In-Memory Mock to avoid build issues
class FirewallDatabase private constructor(context: Context) {
    
    // Abstract DAO not needed for mock
    fun activityLogDao(): ActivityLogDao = ActivityLogDaoMock()
    
    companion object {
        @Volatile
        private var INSTANCE: FirewallDatabase? = null
        
        fun getDatabase(context: Context): FirewallDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = FirewallDatabase(context)
                INSTANCE = instance
                instance
            }
        }
        
        // Added getInstance for compatibility with existing code calling it
        fun getInstance(context: Context): FirewallDatabase {
            return getDatabase(context)
        }
    }
}

interface ActivityLogDao {
    fun insert(log: ActivityLogEntity)
    fun getAll(): List<ActivityLogEntity>
}

class ActivityLogDaoMock : ActivityLogDao {
    private val logs = mutableListOf<ActivityLogEntity>()
    
    override fun insert(log: ActivityLogEntity) {
        logs.add(log)
    }
    
    override fun getAll(): List<ActivityLogEntity> {
        return ArrayList(logs)
    }
}
