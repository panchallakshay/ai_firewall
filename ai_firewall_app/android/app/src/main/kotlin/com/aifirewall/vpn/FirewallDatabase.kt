package com.aifirewall.vpn

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(entities = [ActivityLogEntity::class], version = 1, exportSchema = false)
abstract class FirewallDatabase : RoomDatabase() {
    abstract fun activityLogDao(): ActivityLogDao
    
    companion object {
        @Volatile
        private var INSTANCE: FirewallDatabase? = null
        
        fun getDatabase(context: Context): FirewallDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    FirewallDatabase::class.java,
                    "firewall_database"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}

interface ActivityLogDao {
    // Basic DAO interface to satisfy compiler
    fun insert(log: ActivityLogEntity)
    fun getAll(): List<ActivityLogEntity>
}
