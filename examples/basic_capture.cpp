/**
 * Basic Packet Capture Example
 *
 * This example demonstrates:
 * - Listing network interfaces
 * - Capturing packets from a network interface
 * - Reading packets from a PCAP file
 * - Applying BPF filters
 * - Displaying packet statistics
 */

#include "core/packet_capture.h"
#include "core/version.h"
#include <iostream>
#include <iomanip>
#include <csignal>
#include <atomic>

using namespace netguardian::core;

// Global capture instance for signal handling
static PacketCapturePtr g_capture;
static std::atomic<uint64_t> g_packet_count(0);

/**
 * Signal handler for graceful shutdown
 */
void signal_handler(int signum) {
    std::cout << "\n[INFO] Caught signal " << signum << ", stopping capture...\n";
    if (g_capture) {
        g_capture->stop();
    }
}

/**
 * Packet callback function
 */
void packet_handler(const Packet& packet, void* user_data) {
    g_packet_count++;

    // Print packet info every 100 packets
    if (g_packet_count % 100 == 0) {
        std::cout << "[INFO] Captured " << g_packet_count << " packets...\n";
    }

    // Optionally print detailed info for first few packets
    if (g_packet_count <= 5) {
        auto ts = packet.timestamp();
        auto ts_t = std::chrono::system_clock::to_time_t(ts);

        std::cout << "\nPacket #" << g_packet_count << "\n";
        std::cout << "  Timestamp: " << std::ctime(&ts_t);
        std::cout << "  Length: " << packet.length() << " bytes\n";
        std::cout << "  Captured: " << packet.caplen() << " bytes\n";
    }
}

/**
 * List available network interfaces
 */
void list_interfaces() {
    std::vector<std::string> interfaces;

    std::cout << "\nAvailable Network Interfaces:\n";
    std::cout << "==============================\n\n";

    if (PacketCapture::list_interfaces(interfaces)) {
        if (interfaces.empty()) {
            std::cout << "No interfaces found.\n";
        } else {
            for (size_t i = 0; i < interfaces.size(); ++i) {
                std::cout << "  [" << i << "] " << interfaces[i] << "\n";
            }
        }
    } else {
        std::cerr << "[ERROR] Failed to list interfaces\n";
    }
    std::cout << "\n";
}

/**
 * Capture from network interface
 */
int capture_live(const std::string& interface, const std::string& filter,
                 int packet_count) {
    std::cout << "\nLive Packet Capture\n";
    std::cout << "===================\n";
    std::cout << "Interface: " << interface << "\n";
    if (!filter.empty()) {
        std::cout << "Filter: " << filter << "\n";
    }
    std::cout << "Packet count: " << (packet_count == 0 ? "unlimited" : std::to_string(packet_count)) << "\n";
    std::cout << "\nPress Ctrl+C to stop...\n\n";

    // Configure capture
    CaptureConfig config;
    config.interface = interface;
    config.filter = filter;
    config.promiscuous = true;
    config.snaplen = 65535;
    config.timeout_ms = 1000;

    // Create capture instance
    g_capture = std::make_shared<PacketCapture>(config);

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Start capture
    if (!g_capture->start()) {
        std::cerr << "[ERROR] Failed to start capture: " << g_capture->get_error() << "\n";
        return 1;
    }

    std::cout << "[INFO] Capture started successfully\n";
    std::cout << "[INFO] Data link type: " << g_capture->get_datalink() << "\n";
    std::cout << "[INFO] Snapshot length: " << g_capture->get_snaplen() << " bytes\n\n";

    // Set callback
    g_capture->set_callback(packet_handler, nullptr);

    // Start capture loop
    int result = g_capture->loop(packet_count);

    // Print statistics
    CaptureStats stats;
    if (g_capture->get_stats(&stats)) {
        std::cout << "\nCapture Statistics:\n";
        std::cout << "===================\n";
        std::cout << "  Packets received:  " << stats.packets_received << "\n";
        std::cout << "  Packets dropped:   " << stats.packets_dropped << "\n";
        std::cout << "  Interface drops:   " << stats.packets_dropped_if << "\n";
        std::cout << "  Bytes received:    " << stats.bytes_received << "\n";
        std::cout << "\n";
    }

    return result >= 0 ? 0 : 1;
}

/**
 * Read from PCAP file
 */
int capture_offline(const std::string& filename, const std::string& filter) {
    std::cout << "\nPCAP File Analysis\n";
    std::cout << "==================\n";
    std::cout << "File: " << filename << "\n";
    if (!filter.empty()) {
        std::cout << "Filter: " << filter << "\n";
    }
    std::cout << "\n";

    // Configure capture
    CaptureConfig config;
    config.pcap_file = filename;
    config.filter = filter;

    // Create capture instance
    auto capture = std::make_shared<PacketCapture>(config);

    // Start reading
    if (!capture->start()) {
        std::cerr << "[ERROR] Failed to open file: " << capture->get_error() << "\n";
        return 1;
    }

    std::cout << "[INFO] File opened successfully\n";
    std::cout << "[INFO] Data link type: " << capture->get_datalink() << "\n\n";

    // Set callback
    capture->set_callback(packet_handler, nullptr);

    // Read all packets
    int result = capture->loop(0);

    // Print statistics
    CaptureStats stats;
    if (capture->get_stats(&stats)) {
        std::cout << "\nFile Statistics:\n";
        std::cout << "================\n";
        std::cout << "  Total packets:  " << stats.packets_received << "\n";
        std::cout << "  Total bytes:    " << stats.bytes_received << "\n";
        std::cout << "\n";
    }

    return result >= 0 ? 0 : 1;
}

/**
 * Print usage information
 */
void print_usage(const char* program) {
    std::cout << "Usage: " << program << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -i <interface>  Capture from network interface\n";
    std::cout << "  -r <file>       Read packets from PCAP file\n";
    std::cout << "  -f <filter>     Apply BPF filter (e.g., 'tcp port 80')\n";
    std::cout << "  -c <count>      Capture N packets then exit (0 = unlimited)\n";
    std::cout << "  -l              List available interfaces\n";
    std::cout << "  -h, --help      Show this help\n";
    std::cout << "\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program << " -l\n";
    std::cout << "  " << program << " -i eth0\n";
    std::cout << "  " << program << " -i eth0 -f \"tcp port 80\" -c 100\n";
    std::cout << "  " << program << " -r capture.pcap\n";
    std::cout << "  " << program << " -r capture.pcap -f \"host 192.168.1.1\"\n";
    std::cout << "\n";
}

int main(int argc, char* argv[]) {
    std::cout << "NetGuardian Basic Capture Example\n";
    std::cout << "Version " << netguardian::VERSION << "\n";
    std::cout << "==================================\n";

    // Parse arguments
    std::string interface;
    std::string pcap_file;
    std::string filter;
    int count = 0;
    bool list = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
        else if (arg == "-l") {
            list = true;
        }
        else if (arg == "-i" && i + 1 < argc) {
            interface = argv[++i];
        }
        else if (arg == "-r" && i + 1 < argc) {
            pcap_file = argv[++i];
        }
        else if (arg == "-f" && i + 1 < argc) {
            filter = argv[++i];
        }
        else if (arg == "-c" && i + 1 < argc) {
            count = std::atoi(argv[++i]);
        }
        else {
            std::cerr << "[ERROR] Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // Handle list interfaces
    if (list) {
        list_interfaces();
        return 0;
    }

    // Handle live capture
    if (!interface.empty()) {
        return capture_live(interface, filter, count);
    }

    // Handle offline capture
    if (!pcap_file.empty()) {
        return capture_offline(pcap_file, filter);
    }

    // No valid options
    std::cerr << "[ERROR] No interface (-i) or file (-r) specified\n\n";
    print_usage(argv[0]);
    return 1;
}
