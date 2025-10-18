#ifndef NETGUARDIAN_CORE_PACKET_CAPTURE_H
#define NETGUARDIAN_CORE_PACKET_CAPTURE_H

#include "core/packet.h"
#include <pcap/pcap.h>
#include <string>
#include <functional>
#include <memory>
#include <atomic>

namespace netguardian {
namespace core {

/**
 * Packet capture callback function type
 * Parameters: packet pointer, user data
 */
using PacketCallback = std::function<void(const Packet&, void*)>;

/**
 * Packet capture statistics
 */
struct CaptureStats {
    uint64_t packets_received;    // Total packets received
    uint64_t packets_dropped;     // Packets dropped by kernel
    uint64_t packets_dropped_if;  // Packets dropped by interface
    uint64_t bytes_received;      // Total bytes received

    CaptureStats()
        : packets_received(0)
        , packets_dropped(0)
        , packets_dropped_if(0)
        , bytes_received(0)
    {}
};

/**
 * Packet capture configuration
 */
struct CaptureConfig {
    std::string interface;        // Network interface name (e.g., "eth0")
    std::string pcap_file;        // PCAP file path (for offline mode)
    int snaplen;                  // Snapshot length (max bytes per packet)
    int timeout_ms;               // Read timeout in milliseconds
    int buffer_size;              // Kernel buffer size in bytes
    bool promiscuous;             // Enable promiscuous mode
    std::string filter;           // BPF filter expression

    CaptureConfig()
        : interface("")
        , pcap_file("")
        , snaplen(65535)          // Default: capture full packet
        , timeout_ms(1000)        // Default: 1 second timeout
        , buffer_size(2 * 1024 * 1024)  // Default: 2MB
        , promiscuous(true)       // Default: promiscuous mode on
        , filter("")
    {}
};

/**
 * PacketCapture class - Handles packet capture using libpcap
 *
 * This class provides interfaces for:
 * - Live packet capture from network interfaces
 * - Offline packet reading from PCAP files
 * - BPF filtering
 * - Capture statistics
 *
 * Example usage:
 * @code
 * CaptureConfig config;
 * config.interface = "eth0";
 * config.filter = "tcp port 80";
 *
 * PacketCapture capture(config);
 * if (capture.start()) {
 *     capture.set_callback([](const Packet& pkt, void* user) {
 *         // Process packet
 *     });
 *     capture.loop(0);  // Capture until stopped
 * }
 * @endcode
 */
class PacketCapture {
public:
    /**
     * Constructor
     * @param config Capture configuration
     */
    explicit PacketCapture(const CaptureConfig& config);

    /**
     * Destructor - automatically closes capture handle
     */
    ~PacketCapture();

    // Disable copy
    PacketCapture(const PacketCapture&) = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    /**
     * Start packet capture
     * @return true on success, false on error
     */
    bool start();

    /**
     * Stop packet capture
     */
    void stop();

    /**
     * Check if capture is active
     * @return true if capturing, false otherwise
     */
    bool is_running() const { return running_; }

    /**
     * Set packet callback function
     * @param callback Function to call for each packet
     * @param user_data User data passed to callback
     */
    void set_callback(PacketCallback callback, void* user_data = nullptr);

    /**
     * Start capture loop
     * @param count Number of packets to capture (0 = infinite)
     * @return Number of packets captured, -1 on error
     */
    int loop(int count = 0);

    /**
     * Process next packet (non-blocking if timeout set)
     * @return 1 if packet received, 0 if timeout, -1 on error, -2 if stopped
     */
    int dispatch_one();

    /**
     * Get capture statistics
     * @param stats Pointer to stats structure to fill
     * @return true on success, false on error
     */
    bool get_stats(CaptureStats* stats) const;

    /**
     * Get last error message
     * @return Error message string
     */
    std::string get_error() const { return error_msg_; }

    /**
     * Get data link type (e.g., DLT_EN10MB for Ethernet)
     * @return Data link type
     */
    int get_datalink() const;

    /**
     * Get snapshot length
     * @return Snapshot length in bytes
     */
    int get_snaplen() const;

    /**
     * List available network interfaces
     * @param interfaces Vector to fill with interface names
     * @return true on success, false on error
     */
    static bool list_interfaces(std::vector<std::string>& interfaces);

private:
    /**
     * Internal libpcap callback handler
     */
    static void pcap_handler(u_char* user, const struct pcap_pkthdr* header,
                             const u_char* bytes);

    /**
     * Apply BPF filter
     * @return true on success, false on error
     */
    bool apply_filter();

    /**
     * Initialize for live capture
     * @return true on success, false on error
     */
    bool init_live_capture();

    /**
     * Initialize for offline capture (PCAP file)
     * @return true on success, false on error
     */
    bool init_offline_capture();

private:
    CaptureConfig config_;
    pcap_t* pcap_handle_;
    PacketCallback callback_;
    void* user_data_;
    std::atomic<bool> running_;
    std::string error_msg_;
    mutable CaptureStats stats_;
};

using PacketCapturePtr = std::shared_ptr<PacketCapture>;

} // namespace core
} // namespace netguardian

#endif // NETGUARDIAN_CORE_PACKET_CAPTURE_H
