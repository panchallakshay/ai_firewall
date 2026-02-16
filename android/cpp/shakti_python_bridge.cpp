#include "shakti_packet_bridge.h"
#include <Python.h>
#include <android/log.h>
#include <mutex>

#define LOG_TAG "ShaktiPython"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace shakti {

class PythonBridge {
public:
    PythonBridge() : initialized_(false), ai_core_module_(nullptr) {}
    
    ~PythonBridge() {
        shutdown();
    }
    
    bool init(const std::string& python_home) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (initialized_) {
            LOGW("PythonBridge already initialized");
            return true;
        }
        
        // Set Python home (where Python libraries are located)
        if (!python_home.empty()) {
            Py_SetPythonHome(Py_DecodeLocale(python_home.c_str(), nullptr));
        }
        
        // Initialize Python interpreter
        Py_Initialize();
        
        if (!Py_IsInitialized()) {
            LOGE("Failed to initialize Python interpreter");
            return false;
        }
        
        LOGI("Python interpreter initialized");
        
        // Add shakti-x-ai directory to Python path
        PyRun_SimpleString("import sys");
        PyRun_SimpleString("sys.path.append('/data/data/com.shakti.firewall/files/python')");
        
        // Import AI core module
        ai_core_module_ = PyImport_ImportModule("ml_engine.shakti_x_ai_core");
        
        if (!ai_core_module_) {
            LOGE("Failed to import ml_engine.shakti_x_ai_core");
            PyErr_Print();
            return false;
        }
        
        LOGI("Imported ml_engine.shakti_x_ai_core successfully");
        
        // Get AICore class
        PyObject* ai_core_class = PyObject_GetAttrString(ai_core_module_, "AICore");
        if (!ai_core_class) {
            LOGE("Failed to get AICore class");
            PyErr_Print();
            return false;
        }
        
        // Create AICore instance
        ai_core_instance_ = PyObject_CallObject(ai_core_class, nullptr);
        Py_DECREF(ai_core_class);
        
        if (!ai_core_instance_) {
            LOGE("Failed to create AICore instance");
            PyErr_Print();
            return false;
        }
        
        LOGI("AICore instance created successfully");
        
        initialized_ = true;
        return true;
    }
    
    bool process_packet(const PacketMetadata& metadata, std::string& result) {
        if (!initialized_) {
            LOGE("PythonBridge not initialized");
            return false;
        }
        
        // Acquire GIL (Global Interpreter Lock)
        PyGILState_STATE gstate = PyGILState_Ensure();
        
        // Create Python dictionary for packet metadata
        PyObject* packet_dict = PyDict_New();
        
        PyDict_SetItemString(packet_dict, "src_ip", 
            PyUnicode_FromString(metadata.src_ip_str().c_str()));
        PyDict_SetItemString(packet_dict, "dst_ip", 
            PyUnicode_FromString(metadata.dst_ip_str().c_str()));
        PyDict_SetItemString(packet_dict, "src_port", PyLong_FromLong(metadata.src_port));
        PyDict_SetItemString(packet_dict, "dst_port", PyLong_FromLong(metadata.dst_port));
        PyDict_SetItemString(packet_dict, "protocol", 
            PyLong_FromLong(static_cast<int>(metadata.protocol)));
        PyDict_SetItemString(packet_dict, "payload_size", 
            PyLong_FromLong(metadata.payload_size));
        PyDict_SetItemString(packet_dict, "timestamp", 
            PyLong_FromLongLong(metadata.timestamp_ms));
        
        // Call ai_core.process_packet(packet_dict)
        PyObject* process_method = PyObject_GetAttrString(ai_core_instance_, "process_packet");
        if (!process_method) {
            LOGE("Failed to get process_packet method");
            PyErr_Print();
            Py_DECREF(packet_dict);
            PyGILState_Release(gstate);
            return false;
        }
        
        PyObject* args = PyTuple_Pack(1, packet_dict);
        PyObject* py_result = PyObject_CallObject(process_method, args);
        
        Py_DECREF(args);
        Py_DECREF(packet_dict);
        Py_DECREF(process_method);
        
        if (!py_result) {
            LOGE("Error calling process_packet");
            PyErr_Print();
            PyGILState_Release(gstate);
            return false;
        }
        
        // Extract result (assuming it returns a string or dict)
        if (PyUnicode_Check(py_result)) {
            const char* str = PyUnicode_AsUTF8(py_result);
            if (str) {
                result = str;
            }
        } else if (PyDict_Check(py_result)) {
            // Convert dict to JSON-like string
            PyObject* str_repr = PyObject_Str(py_result);
            if (str_repr) {
                const char* str = PyUnicode_AsUTF8(str_repr);
                if (str) {
                    result = str;
                }
                Py_DECREF(str_repr);
            }
        }
        
        Py_DECREF(py_result);
        
        // Release GIL
        PyGILState_Release(gstate);
        
        return true;
    }
    
    void shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (!initialized_) {
            return;
        }
        
        // Clean up Python objects
        if (ai_core_instance_) {
            Py_DECREF(ai_core_instance_);
            ai_core_instance_ = nullptr;
        }
        
        if (ai_core_module_) {
            Py_DECREF(ai_core_module_);
            ai_core_module_ = nullptr;
        }
        
        // Finalize Python interpreter
        if (Py_IsInitialized()) {
            Py_Finalize();
        }
        
        initialized_ = false;
        LOGI("PythonBridge shutdown complete");
    }
    
private:
    bool initialized_;
    PyObject* ai_core_module_;
    PyObject* ai_core_instance_;
    std::mutex mutex_;
};

// Global Python bridge instance
static std::unique_ptr<PythonBridge> g_python_bridge;
static std::mutex g_python_mutex;

// Initialize Python bridge
bool python_bridge_init(const std::string& python_home) {
    std::lock_guard<std::mutex> lock(g_python_mutex);
    
    if (!g_python_bridge) {
        g_python_bridge = std::make_unique<PythonBridge>();
    }
    
    return g_python_bridge->init(python_home);
}

// Process packet through Python AI engine
bool python_bridge_process_packet(const PacketMetadata& metadata, std::string& result) {
    std::lock_guard<std::mutex> lock(g_python_mutex);
    
    if (!g_python_bridge) {
        LOGE("Python bridge not initialized");
        return false;
    }
    
    return g_python_bridge->process_packet(metadata, result);
}

// Shutdown Python bridge
void python_bridge_shutdown() {
    std::lock_guard<std::mutex> lock(g_python_mutex);
    
    if (g_python_bridge) {
        g_python_bridge->shutdown();
        g_python_bridge.reset();
    }
}

} // namespace shakti
