#ifndef SHAKTI_PACKET_BRIDGE_H
#define SHAKTI_PACKET_BRIDGE_H

#include <cstdint>
#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <functional>

namespace shakti {

// Protocol types
enum class Protocol : uint8_t {
    TCP = 6,
    UDP = 17,
    ICMP = 1,
    UNKNOWN = 0
};

// Packet direction
enum class Direction : uint8_t {
    INBOUND = 0,
    OUTBOUND = 1
};

// Packet metadata structure (compact for JNI/Python marshalling)
struct PacketMetadata {
    uint32_t src_ip;           // Source IP (network byte order)
    uint32_t dst_ip;           // Destination IP (network byte order)
    uint16_t src_port;         // Source port
    uint16_t dst_port;         // Destination port
    Protocol protocol;         // Protocol type
    Direction direction;       // Packet direction
    uint32_t payload_size;     // Payload size in bytes
    uint64_t timestamp_ms;     // Timestamp in milliseconds
    uint16_t tcp_flags;        // TCP flags (SYN, ACK, etc.)
    
    // Convert IP to string format
    std::string src_ip_str() const;
    std::string dst_ip_str() const;
};

// Packet data container
struct Packet {
    PacketMetadata metadata;
    std::vector<uint8_t> data;  // Raw packet bytes
    
    Packet() = default;
    Packet(const uint8_t* buffer, size_t size);
};

// Thread-safe packet queue
class PacketQueue {
public:
    PacketQueue(size_t max_size = 10000);
    ~PacketQueue() = default;
    
    // Push packet (blocks if queue is full)
    bool push(const Packet& packet, uint32_t timeout_ms = 100);
    
    // Pop packet (blocks if queue is empty)
    bool pop(Packet& packet, uint32_t timeout_ms = 100);
    
    // Non-blocking operations
    bool try_push(const Packet& packet);
    bool try_pop(Packet& packet);
    
    size_t size() const;
    bool empty() const;
    void clear();
    
private:
    std::queue<Packet> queue_;
    mutable std::mutex mutex_;
    std::condition_variable cv_not_full_;
    std::condition_variable cv_not_empty_;
    size_t max_size_;
};

// Packet capture engine
class PacketCaptureEngine {
public:
    PacketCaptureEngine();
    ~PacketCaptureEngine();
    
    // Initialize capture from VPN file descriptor
    bool init(int vpn_fd);
    
    // Capture single packet from VPN interface
    bool capture_packet(Packet& packet);
    
    // Parse raw packet data into metadata
    static bool parse_packet(const uint8_t* data, size_t size, PacketMetadata& metadata);
    
    // Shutdown capture
    void shutdown();
    
private:
    int vpn_fd_;
    bool initialized_;
    std::vector<uint8_t> buffer_;
    
    // Parse IP header
    static bool parse_ip_header(const uint8_t* data, size_t size, PacketMetadata& metadata);
    
    // Parse TCP header
    static bool parse_tcp_header(const uint8_t* data, size_t size, PacketMetadata& metadata);
    
    // Parse UDP header
    static bool parse_udp_header(const uint8_t* data, size_t size, PacketMetadata& metadata);
};

// Packet forwarder (sends packets to real internet)
class PacketForwarder {
public:
    PacketForwarder();
    ~PacketForwarder();
    
    // Initialize forwarder
    bool init();
    
    // Forward packet to internet
    bool forward_packet(const Packet& packet);
    
    // Forward TCP packet
    bool forward_tcp(const Packet& packet);
    
    // Forward UDP packet
    bool forward_udp(const Packet& packet);
    
    // Cleanup old connections
    void cleanup_connections();
    
    // Shutdown forwarder
    void shutdown();
    
private:
    struct TCPConnection {
        int socket_fd;
        uint32_t src_ip;
        uint16_t src_port;
        uint32_t dst_ip;
        uint16_t dst_port;
        uint64_t last_used_ms;
    };
    
    struct UDPMapping {
        int socket_fd;
        uint32_t src_ip;
        uint16_t src_port;
        uint32_t dst_ip;
        uint16_t dst_port;
        uint64_t last_used_ms;
    };
    
    bool initialized_;
    std::mutex tcp_mutex_;
    std::mutex udp_mutex_;
    
    // Connection tracking
    std::map<std::string, TCPConnection> tcp_connections_;
    std::map<std::string, UDPMapping> udp_mappings_;
    
    // Helper functions
    std::string make_connection_key(uint32_t src_ip, uint16_t src_port, 
                                    uint32_t dst_ip, uint16_t dst_port);
    int create_tcp_socket(uint32_t dst_ip, uint16_t dst_port);
    int create_udp_socket();
};

// Callback type for Python integration
using PythonCallback = std::function<void(const PacketMetadata&, const std::string&)>;

// Main packet bridge (orchestrates all components)
class PacketBridge {
public:
    PacketBridge();
    ~PacketBridge();
    
    // Initialize bridge with VPN file descriptor
    bool init(int vpn_fd);
    
    // Start packet processing
    bool start();
    
    // Stop packet processing
    void stop();
    
    // Process single packet (for synchronous mode)
    bool process_packet(const uint8_t* data, size_t size);
    
    // Register callback for Python AI engine
    void register_python_callback(PythonCallback callback);
    
    // Get statistics
    struct Stats {
        uint64_t packets_captured;
        uint64_t packets_forwarded;
        uint64_t packets_dropped;
        uint64_t bytes_processed;
    };
    Stats get_stats() const;
    
private:
    PacketCaptureEngine capture_engine_;
    PacketForwarder forwarder_;
    PacketQueue capture_queue_;
    PacketQueue forward_queue_;
    
    PythonCallback python_callback_;
    
    bool initialized_;
    bool running_;
    
    mutable std::mutex stats_mutex_;
    Stats stats_;
    
    // Worker thread functions
    void capture_worker();
    void forward_worker();
    void python_worker();
    
    std::vector<std::thread> worker_threads_;
};

} // namespace shakti

#endif // SHAKTI_PACKET_BRIDGE_H
