#include "shakti_packet_bridge.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <chrono>
#include <android/log.h>

#define LOG_TAG "ShaktiBridge"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace shakti {

// ============================================================================
// PacketMetadata Implementation
// ============================================================================

std::string PacketMetadata::src_ip_str() const {
    struct in_addr addr;
    addr.s_addr = src_ip;
    return inet_ntoa(addr);
}

std::string PacketMetadata::dst_ip_str() const {
    struct in_addr addr;
    addr.s_addr = dst_ip;
    return inet_ntoa(addr);
}

// ============================================================================
// Packet Implementation
// ============================================================================

Packet::Packet(const uint8_t* buffer, size_t size) {
    data.assign(buffer, buffer + size);
}

// ============================================================================
// PacketQueue Implementation
// ============================================================================

PacketQueue::PacketQueue(size_t max_size) : max_size_(max_size) {}

bool PacketQueue::push(const Packet& packet, uint32_t timeout_ms) {
    std::unique_lock<std::mutex> lock(mutex_);
    
    if (!cv_not_full_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                [this] { return queue_.size() < max_size_; })) {
        return false; // Timeout
    }
    
    queue_.push(packet);
    cv_not_empty_.notify_one();
    return true;
}

bool PacketQueue::pop(Packet& packet, uint32_t timeout_ms) {
    std::unique_lock<std::mutex> lock(mutex_);
    
    if (!cv_not_empty_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                 [this] { return !queue_.empty(); })) {
        return false; // Timeout
    }
    
    packet = queue_.front();
    queue_.pop();
    cv_not_full_.notify_one();
    return true;
}

bool PacketQueue::try_push(const Packet& packet) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.size() >= max_size_) {
        return false;
    }
    queue_.push(packet);
    cv_not_empty_.notify_one();
    return true;
}

bool PacketQueue::try_pop(Packet& packet) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty()) {
        return false;
    }
    packet = queue_.front();
    queue_.pop();
    cv_not_full_.notify_one();
    return true;
}

size_t PacketQueue::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

bool PacketQueue::empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
}

void PacketQueue::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    while (!queue_.empty()) {
        queue_.pop();
    }
}

// ============================================================================
// PacketCaptureEngine Implementation
// ============================================================================

PacketCaptureEngine::PacketCaptureEngine() 
    : vpn_fd_(-1), initialized_(false), buffer_(65536) {}

PacketCaptureEngine::~PacketCaptureEngine() {
    shutdown();
}

bool PacketCaptureEngine::init(int vpn_fd) {
    if (vpn_fd < 0) {
        LOGE("Invalid VPN file descriptor");
        return false;
    }
    
    vpn_fd_ = vpn_fd;
    initialized_ = true;
    LOGI("PacketCaptureEngine initialized with fd=%d", vpn_fd);
    return true;
}

bool PacketCaptureEngine::capture_packet(Packet& packet) {
    if (!initialized_) {
        LOGE("PacketCaptureEngine not initialized");
        return false;
    }
    
    // Read from VPN file descriptor
    ssize_t length = read(vpn_fd_, buffer_.data(), buffer_.size());
    
    if (length < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return false; // No data available
        }
        LOGE("Error reading from VPN fd: %s", strerror(errno));
        return false;
    }
    
    if (length == 0) {
        return false; // No data
    }
    
    // Parse packet
    if (!parse_packet(buffer_.data(), length, packet.metadata)) {
        LOGD("Failed to parse packet");
        return false;
    }
    
    // Copy packet data
    packet.data.assign(buffer_.data(), buffer_.data() + length);
    
    return true;
}

bool PacketCaptureEngine::parse_packet(const uint8_t* data, size_t size, 
                                       PacketMetadata& metadata) {
    if (size < sizeof(struct iphdr)) {
        return false;
    }
    
    return parse_ip_header(data, size, metadata);
}

bool PacketCaptureEngine::parse_ip_header(const uint8_t* data, size_t size, 
                                          PacketMetadata& metadata) {
    const struct iphdr* ip = reinterpret_cast<const struct iphdr*>(data);
    
    // Only support IPv4
    if (ip->version != 4) {
        return false;
    }
    
    // Extract IP header info
    metadata.src_ip = ip->saddr;
    metadata.dst_ip = ip->daddr;
    metadata.protocol = static_cast<Protocol>(ip->protocol);
    metadata.payload_size = ntohs(ip->tot_len);
    metadata.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    // Determine direction (simple heuristic: 10.0.0.x is VPN internal)
    uint8_t first_octet = (metadata.src_ip >> 24) & 0xFF;
    metadata.direction = (first_octet == 10) ? Direction::OUTBOUND : Direction::INBOUND;
    
    // Get IP header length
    size_t ip_header_len = ip->ihl * 4;
    if (size < ip_header_len) {
        return false;
    }
    
    const uint8_t* transport_layer = data + ip_header_len;
    size_t transport_size = size - ip_header_len;
    
    // Parse transport layer
    switch (metadata.protocol) {
        case Protocol::TCP:
            return parse_tcp_header(transport_layer, transport_size, metadata);
        case Protocol::UDP:
            return parse_udp_header(transport_layer, transport_size, metadata);
        default:
            // Other protocols (ICMP, etc.)
            metadata.src_port = 0;
            metadata.dst_port = 0;
            metadata.tcp_flags = 0;
            return true;
    }
}

bool PacketCaptureEngine::parse_tcp_header(const uint8_t* data, size_t size, 
                                           PacketMetadata& metadata) {
    if (size < sizeof(struct tcphdr)) {
        return false;
    }
    
    const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(data);
    
    metadata.src_port = ntohs(tcp->source);
    metadata.dst_port = ntohs(tcp->dest);
    
    // Extract TCP flags
    metadata.tcp_flags = 0;
    if (tcp->syn) metadata.tcp_flags |= (1 << 1);
    if (tcp->ack) metadata.tcp_flags |= (1 << 4);
    if (tcp->fin) metadata.tcp_flags |= (1 << 0);
    if (tcp->rst) metadata.tcp_flags |= (1 << 2);
    if (tcp->psh) metadata.tcp_flags |= (1 << 3);
    
    return true;
}

bool PacketCaptureEngine::parse_udp_header(const uint8_t* data, size_t size, 
                                           PacketMetadata& metadata) {
    if (size < sizeof(struct udphdr)) {
        return false;
    }
    
    const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(data);
    
    metadata.src_port = ntohs(udp->source);
    metadata.dst_port = ntohs(udp->dest);
    metadata.tcp_flags = 0;
    
    return true;
}

void PacketCaptureEngine::shutdown() {
    initialized_ = false;
    // Note: We don't close vpn_fd_ as it's managed by Java/Kotlin layer
}

// ============================================================================
// PacketForwarder Implementation
// ============================================================================

PacketForwarder::PacketForwarder() : initialized_(false) {}

PacketForwarder::~PacketForwarder() {
    shutdown();
}

bool PacketForwarder::init() {
    initialized_ = true;
    LOGI("PacketForwarder initialized");
    return true;
}

bool PacketForwarder::forward_packet(const Packet& packet) {
    if (!initialized_) {
        LOGE("PacketForwarder not initialized");
        return false;
    }
    
    switch (packet.metadata.protocol) {
        case Protocol::TCP:
            return forward_tcp(packet);
        case Protocol::UDP:
            return forward_udp(packet);
        default:
            LOGD("Unsupported protocol: %d", static_cast<int>(packet.metadata.protocol));
            return false;
    }
}

std::string PacketForwarder::make_connection_key(uint32_t src_ip, uint16_t src_port,
                                                 uint32_t dst_ip, uint16_t dst_port) {
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%u:%u->%u:%u", src_ip, src_port, dst_ip, dst_port);
    return std::string(buffer);
}

int PacketForwarder::create_tcp_socket(uint32_t dst_ip, uint16_t dst_port) {
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        LOGE("Failed to create TCP socket: %s", strerror(errno));
        return -1;
    }
    
    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    // Set socket options
    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Connect to destination
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = dst_ip;
    addr.sin_port = htons(dst_port);
    
    int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (result < 0 && errno != EINPROGRESS) {
        LOGE("Failed to connect TCP socket: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    return sock;
}

int PacketForwarder::create_udp_socket() {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        LOGE("Failed to create UDP socket: %s", strerror(errno));
        return -1;
    }
    
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    return sock;
}

bool PacketForwarder::forward_tcp(const Packet& packet) {
    std::lock_guard<std::mutex> lock(tcp_mutex_);
    
    std::string key = make_connection_key(
        packet.metadata.src_ip, packet.metadata.src_port,
        packet.metadata.dst_ip, packet.metadata.dst_port
    );
    
    // Get or create connection
    auto it = tcp_connections_.find(key);
    if (it == tcp_connections_.end()) {
        // Create new connection
        int sock = create_tcp_socket(packet.metadata.dst_ip, packet.metadata.dst_port);
        if (sock < 0) {
            return false;
        }
        
        TCPConnection conn;
        conn.socket_fd = sock;
        conn.src_ip = packet.metadata.src_ip;
        conn.src_port = packet.metadata.src_port;
        conn.dst_ip = packet.metadata.dst_ip;
        conn.dst_port = packet.metadata.dst_port;
        conn.last_used_ms = packet.metadata.timestamp_ms;
        
        tcp_connections_[key] = conn;
        LOGD("Created TCP connection: %s -> %s:%d", 
             key.c_str(), packet.metadata.dst_ip_str().c_str(), packet.metadata.dst_port);
    } else {
        it->second.last_used_ms = packet.metadata.timestamp_ms;
    }
    
    // Extract payload (skip IP and TCP headers)
    const struct iphdr* ip = reinterpret_cast<const struct iphdr*>(packet.data.data());
    size_t ip_header_len = ip->ihl * 4;
    const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(
        packet.data.data() + ip_header_len
    );
    size_t tcp_header_len = tcp->doff * 4;
    size_t header_total = ip_header_len + tcp_header_len;
    
    if (packet.data.size() <= header_total) {
        return true; // No payload (ACK, SYN, etc.)
    }
    
    const uint8_t* payload = packet.data.data() + header_total;
    size_t payload_len = packet.data.size() - header_total;
    
    // Send to real server
    ssize_t sent = send(tcp_connections_[key].socket_fd, payload, payload_len, MSG_NOSIGNAL);
    if (sent < 0) {
        LOGE("Failed to send TCP data: %s", strerror(errno));
        close(tcp_connections_[key].socket_fd);
        tcp_connections_.erase(key);
        return false;
    }
    
    LOGD("Forwarded TCP packet: %zu bytes to %s:%d", 
         sent, packet.metadata.dst_ip_str().c_str(), packet.metadata.dst_port);
    
    return true;
}

bool PacketForwarder::forward_udp(const Packet& packet) {
    std::lock_guard<std::mutex> lock(udp_mutex_);
    
    std::string key = make_connection_key(
        packet.metadata.src_ip, packet.metadata.src_port,
        packet.metadata.dst_ip, packet.metadata.dst_port
    );
    
    // Get or create UDP socket
    auto it = udp_mappings_.find(key);
    if (it == udp_mappings_.end()) {
        int sock = create_udp_socket();
        if (sock < 0) {
            return false;
        }
        
        UDPMapping mapping;
        mapping.socket_fd = sock;
        mapping.src_ip = packet.metadata.src_ip;
        mapping.src_port = packet.metadata.src_port;
        mapping.dst_ip = packet.metadata.dst_ip;
        mapping.dst_port = packet.metadata.dst_port;
        mapping.last_used_ms = packet.metadata.timestamp_ms;
        
        udp_mappings_[key] = mapping;
        LOGD("Created UDP mapping: %s", key.c_str());
    } else {
        it->second.last_used_ms = packet.metadata.timestamp_ms;
    }
    
    // Extract payload
    const struct iphdr* ip = reinterpret_cast<const struct iphdr*>(packet.data.data());
    size_t ip_header_len = ip->ihl * 4;
    const uint8_t* payload = packet.data.data() + ip_header_len + sizeof(struct udphdr);
    size_t payload_len = packet.data.size() - ip_header_len - sizeof(struct udphdr);
    
    // Send to destination
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = packet.metadata.dst_ip;
    addr.sin_port = htons(packet.metadata.dst_port);
    
    ssize_t sent = sendto(udp_mappings_[key].socket_fd, payload, payload_len, 0,
                          (struct sockaddr*)&addr, sizeof(addr));
    
    if (sent < 0) {
        LOGE("Failed to send UDP data: %s", strerror(errno));
        return false;
    }
    
    LOGD("Forwarded UDP packet: %zu bytes to %s:%d", 
         sent, packet.metadata.dst_ip_str().c_str(), packet.metadata.dst_port);
    
    return true;
}

void PacketForwarder::cleanup_connections() {
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    uint64_t timeout_ms = 5 * 60 * 1000; // 5 minutes
    
    // Cleanup TCP
    {
        std::lock_guard<std::mutex> lock(tcp_mutex_);
        for (auto it = tcp_connections_.begin(); it != tcp_connections_.end();) {
            if (now - it->second.last_used_ms > timeout_ms) {
                close(it->second.socket_fd);
                it = tcp_connections_.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    // Cleanup UDP
    {
        std::lock_guard<std::mutex> lock(udp_mutex_);
        for (auto it = udp_mappings_.begin(); it != udp_mappings_.end();) {
            if (now - it->second.last_used_ms > timeout_ms) {
                close(it->second.socket_fd);
                it = udp_mappings_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void PacketForwarder::shutdown() {
    // Close all TCP connections
    {
        std::lock_guard<std::mutex> lock(tcp_mutex_);
        for (auto& pair : tcp_connections_) {
            close(pair.second.socket_fd);
        }
        tcp_connections_.clear();
    }
    
    // Close all UDP sockets
    {
        std::lock_guard<std::mutex> lock(udp_mutex_);
        for (auto& pair : udp_mappings_) {
            close(pair.second.socket_fd);
        }
        udp_mappings_.clear();
    }
    
    initialized_ = false;
    LOGI("PacketForwarder shutdown complete");
}

// ============================================================================
// PacketBridge Implementation
// ============================================================================

PacketBridge::PacketBridge() 
    : initialized_(false), running_(false) {
    memset(&stats_, 0, sizeof(stats_));
}

PacketBridge::~PacketBridge() {
    stop();
}

bool PacketBridge::init(int vpn_fd) {
    if (!capture_engine_.init(vpn_fd)) {
        LOGE("Failed to initialize capture engine");
        return false;
    }
    
    if (!forwarder_.init()) {
        LOGE("Failed to initialize forwarder");
        return false;
    }
    
    initialized_ = true;
    LOGI("PacketBridge initialized successfully");
    return true;
}

bool PacketBridge::start() {
    if (!initialized_) {
        LOGE("PacketBridge not initialized");
        return false;
    }
    
    if (running_) {
        LOGE("PacketBridge already running");
        return false;
    }
    
    running_ = true;
    
    // Start worker threads
    worker_threads_.emplace_back(&PacketBridge::capture_worker, this);
    worker_threads_.emplace_back(&PacketBridge::forward_worker, this);
    worker_threads_.emplace_back(&PacketBridge::python_worker, this);
    
    LOGI("PacketBridge started with %zu worker threads", worker_threads_.size());
    return true;
}

void PacketBridge::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    // Wait for threads to finish
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    worker_threads_.clear();
    
    // Cleanup
    capture_engine_.shutdown();
    forwarder_.shutdown();
    
    LOGI("PacketBridge stopped");
}

bool PacketBridge::process_packet(const uint8_t* data, size_t size) {
    Packet packet(data, size);
    
    if (!PacketCaptureEngine::parse_packet(data, size, packet.metadata)) {
        return false;
    }
    
    // Update stats
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.packets_captured++;
        stats_.bytes_processed += size;
    }
    
    // Forward packet
    if (forwarder_.forward_packet(packet)) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.packets_forwarded++;
    } else {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.packets_dropped++;
    }
    
    // Call Python callback if registered
    if (python_callback_) {
        python_callback_(packet.metadata, "");
    }
    
    return true;
}

void PacketBridge::register_python_callback(PythonCallback callback) {
    python_callback_ = callback;
}

PacketBridge::Stats PacketBridge::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void PacketBridge::capture_worker() {
    LOGI("Capture worker started");
    
    while (running_) {
        Packet packet;
        if (capture_engine_.capture_packet(packet)) {
            capture_queue_.push(packet, 10);
            
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.packets_captured++;
            stats_.bytes_processed += packet.data.size();
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    
    LOGI("Capture worker stopped");
}

void PacketBridge::forward_worker() {
    LOGI("Forward worker started");
    
    while (running_) {
        Packet packet;
        if (capture_queue_.pop(packet, 10)) {
            if (forwarder_.forward_packet(packet)) {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.packets_forwarded++;
            } else {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.packets_dropped++;
            }
            
            // Also send to Python worker
            forward_queue_.try_push(packet);
        }
    }
    
    LOGI("Forward worker stopped");
}

void PacketBridge::python_worker() {
    LOGI("Python worker started");
    
    while (running_) {
        Packet packet;
        if (forward_queue_.pop(packet, 10)) {
            if (python_callback_) {
                python_callback_(packet.metadata, "");
            }
        }
    }
    
    LOGI("Python worker stopped");
}

} // namespace shakti
