#include <jni.h>
#include "shakti_packet_bridge.h"
#include <android/log.h>
#include <map>
#include <mutex>

#define LOG_TAG "ShaktiJNI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Global bridge instance management
static std::mutex g_bridge_mutex;
static std::map<jlong, std::unique_ptr<shakti::PacketBridge>> g_bridges;
static jlong g_next_bridge_id = 1;

// Helper: Convert Java byte array to C++ vector
static std::vector<uint8_t> jbyteArrayToVector(JNIEnv* env, jbyteArray array) {
    jsize len = env->GetArrayLength(array);
    std::vector<uint8_t> result(len);
    env->GetByteArrayRegion(array, 0, len, reinterpret_cast<jbyte*>(result.data()));
    return result;
}

// Helper: Create Java PacketMetadata object
static jobject createPacketMetadataObject(JNIEnv* env, const shakti::PacketMetadata& metadata) {
    jclass metadataClass = env->FindClass("com/shakti/bridge/PacketMetadata");
    if (!metadataClass) {
        LOGE("Failed to find PacketMetadata class");
        return nullptr;
    }
    
    jmethodID constructor = env->GetMethodID(metadataClass, "<init>", 
        "(Ljava/lang/String;Ljava/lang/String;IIIIJJ)V");
    
    if (!constructor) {
        LOGE("Failed to find PacketMetadata constructor");
        return nullptr;
    }
    
    jstring srcIp = env->NewStringUTF(metadata.src_ip_str().c_str());
    jstring dstIp = env->NewStringUTF(metadata.dst_ip_str().c_str());
    
    jobject obj = env->NewObject(metadataClass,
        constructor,
        srcIp,
        dstIp,
        metadata.src_port,
        metadata.dst_port,
        static_cast<int>(metadata.protocol),
        static_cast<int>(metadata.direction),
        metadata.payload_size,
        static_cast<jlong>(metadata.timestamp_ms)
    );
    
    env->DeleteLocalRef(srcIp);
    env->DeleteLocalRef(dstIp);
    env->DeleteLocalRef(metadataClass);
    
    return obj;
}

extern "C" {

/*
 * Class:     com_shakti_bridge_PacketBridge
 * Method:    nativeInit
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL
Java_com_shakti_bridge_PacketBridge_nativeInit(JNIEnv* env, jobject thiz, jint vpn_fd) {
    LOGI("nativeInit called with fd=%d", vpn_fd);
    
    try {
        auto bridge = std::make_unique<shakti::PacketBridge>();
        
        if (!bridge->init(vpn_fd)) {
            LOGE("Failed to initialize PacketBridge");
            return 0;
        }
        
        std::lock_guard<std::mutex> lock(g_bridge_mutex);
        jlong bridge_id = g_next_bridge_id++;
        g_bridges[bridge_id] = std::move(bridge);
        
        LOGI("PacketBridge initialized successfully, ID=%lld", bridge_id);
        return bridge_id;
        
    } catch (const std::exception& e) {
        LOGE("Exception in nativeInit: %s", e.what());
        return 0;
    }
}

/*
 * Class:     com_shakti_bridge_PacketBridge
 * Method:    nativeStart
 * Signature: (J)Z
 */
JNIEXPORT jboolean JNICALL
Java_com_shakti_bridge_PacketBridge_nativeStart(JNIEnv* env, jobject thiz, jlong bridge_id) {
    std::lock_guard<std::mutex> lock(g_bridge_mutex);
    
    auto it = g_bridges.find(bridge_id);
    if (it == g_bridges.end()) {
        LOGE("Invalid bridge ID: %lld", bridge_id);
        return JNI_FALSE;
    }
    
    if (it->second->start()) {
        LOGI("PacketBridge started, ID=%lld", bridge_id);
        return JNI_TRUE;
    }
    
    LOGE("Failed to start PacketBridge, ID=%lld", bridge_id);
    return JNI_FALSE;
}

/*
 * Class:     com_shakti_bridge_PacketBridge
 * Method:    nativeStop
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_shakti_bridge_PacketBridge_nativeStop(JNIEnv* env, jobject thiz, jlong bridge_id) {
    std::lock_guard<std::mutex> lock(g_bridge_mutex);
    
    auto it = g_bridges.find(bridge_id);
    if (it == g_bridges.end()) {
        LOGE("Invalid bridge ID: %lld", bridge_id);
        return;
    }
    
    it->second->stop();
    LOGI("PacketBridge stopped, ID=%lld", bridge_id);
}

/*
 * Class:     com_shakti_bridge_PacketBridge
 * Method:    nativeProcessPacket
 * Signature: (J[B)Z
 */
JNIEXPORT jboolean JNICALL
Java_com_shakti_bridge_PacketBridge_nativeProcessPacket(JNIEnv* env, jobject thiz, 
                                                        jlong bridge_id, jbyteArray packet_data) {
    std::lock_guard<std::mutex> lock(g_bridge_mutex);
    
    auto it = g_bridges.find(bridge_id);
    if (it == g_bridges.end()) {
        LOGE("Invalid bridge ID: %lld", bridge_id);
        return JNI_FALSE;
    }
    
    std::vector<uint8_t> data = jbyteArrayToVector(env, packet_data);
    
    if (it->second->process_packet(data.data(), data.size())) {
        return JNI_TRUE;
    }
    
    return JNI_FALSE;
}

/*
 * Class:     com_shakti_bridge_PacketBridge
 * Method:    nativeGetStats
 * Signature: (J)Lcom/shakti/bridge/BridgeStats;
 */
JNIEXPORT jobject JNICALL
Java_com_shakti_bridge_PacketBridge_nativeGetStats(JNIEnv* env, jobject thiz, jlong bridge_id) {
    std::lock_guard<std::mutex> lock(g_bridge_mutex);
    
    auto it = g_bridges.find(bridge_id);
    if (it == g_bridges.end()) {
        LOGE("Invalid bridge ID: %lld", bridge_id);
        return nullptr;
    }
    
    auto stats = it->second->get_stats();
    
    jclass statsClass = env->FindClass("com/shakti/bridge/BridgeStats");
    if (!statsClass) {
        LOGE("Failed to find BridgeStats class");
        return nullptr;
    }
    
    jmethodID constructor = env->GetMethodID(statsClass, "<init>", "(JJJJ)V");
    if (!constructor) {
        LOGE("Failed to find BridgeStats constructor");
        return nullptr;
    }
    
    jobject statsObj = env->NewObject(statsClass, constructor,
        static_cast<jlong>(stats.packets_captured),
        static_cast<jlong>(stats.packets_forwarded),
        static_cast<jlong>(stats.packets_dropped),
        static_cast<jlong>(stats.bytes_processed)
    );
    
    env->DeleteLocalRef(statsClass);
    return statsObj;
}

/*
 * Class:     com_shakti_bridge_PacketBridge
 * Method:    nativeShutdown
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_shakti_bridge_PacketBridge_nativeShutdown(JNIEnv* env, jobject thiz, jlong bridge_id) {
    std::lock_guard<std::mutex> lock(g_bridge_mutex);
    
    auto it = g_bridges.find(bridge_id);
    if (it == g_bridges.end()) {
        LOGE("Invalid bridge ID: %lld", bridge_id);
        return;
    }
    
    it->second->stop();
    g_bridges.erase(it);
    
    LOGI("PacketBridge shutdown complete, ID=%lld", bridge_id);
}

/*
 * Class:     com_shakti_bridge_PacketBridge
 * Method:    nativeParsePacket
 * Signature: ([B)Lcom/shakti/bridge/PacketMetadata;
 */
JNIEXPORT jobject JNICALL
Java_com_shakti_bridge_PacketBridge_nativeParsePacket(JNIEnv* env, jclass clazz, 
                                                      jbyteArray packet_data) {
    std::vector<uint8_t> data = jbyteArrayToVector(env, packet_data);
    
    shakti::PacketMetadata metadata;
    if (!shakti::PacketCaptureEngine::parse_packet(data.data(), data.size(), metadata)) {
        return nullptr;
    }
    
    return createPacketMetadataObject(env, metadata);
}

} // extern "C"
