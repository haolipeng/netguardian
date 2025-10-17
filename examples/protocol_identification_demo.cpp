/**
 * Protocol Identification Demo
 *
 * Demonstrates application-layer protocol identification using:
 * 1. Port-based identification (fast, low accuracy)
 * 2. Deep Packet Inspection - DPI (accurate)
 * 3. Protocol signatures and pattern matching
 */

#include "core/packet_capture.h"
#include "core/protocol_parser.h"
#include "core/app_protocol_identifier.h"
#include "core/version.h"
#include <iostream>
#include <iomanip>
#include <csignal>
#include <atomic>
#include <map>

using namespace netguardian::core;

static PacketCapturePtr g_capture;
static std::atomic<bool> g_running(true);
static AppProtocolIdentifier g_identifier;

// Statistics
static std::map<ProtocolType, uint64_t> g_protocol_stats;
static uint64_t g_total_packets = 0;
static uint64_t g_identified_packets = 0;

void signal_handler(int signum) {
    std::cout << "\n[INFO] Shutting down...\n";
    g_running = false;
    if (g_capture) {
        g_capture->stop();
    }
}

void print_protocol_info(const Packet& packet, const IdentificationResult& result) {
    const ProtocolStack& stack = packet.protocol_stack();
    
    std::cout << "\n=== Packet #" << g_total_packets << " ===\n";
    
    // L2 info
    std::cout << "L2: " << protocol_type_to_string(stack.l2_type);
    if (stack.has_vlan) {
        std::cout << " [VLAN " << stack.vlan_id << "]";
    }
    std::cout << "\n";
    
    // L3 info
    std::cout << "L3: " << protocol_type_to_string(stack.l3_type) << "\n";
    
    // L4 info
    if (stack.l4_type != ProtocolType::UNKNOWN) {
        std::cout << "L4: " << protocol_type_to_string(stack.l4_type);
        
        // Extract and show ports
        if (stack.l4_offset > 0 && (stack.l4_type == ProtocolType::TCP || stack.l4_type == ProtocolType::UDP)) {
            const uint8_t* l4_data = packet.data() + stack.l4_offset;
            uint16_t src_port = ntohs(*reinterpret_cast<const uint16_t*>(l4_data));
            uint16_t dst_port = ntohs(*reinterpret_cast<const uint16_t*>(l4_data + 2));
            std::cout << " [" << src_port << " -> " << dst_port << "]";
        }
        std::cout << "\n";
    }
    
    // L7 info (application protocol)
    std::cout << "L7: ";
    if (result.protocol != ProtocolType::UNKNOWN) {
        std::cout << protocol_type_to_string(result.protocol);
        std::cout << " (confidence: " << result.confidence << "%, method: " << result.method << ")";
        if (!result.details.empty()) {
            std::cout << "\n    Details: " << result.details;
        }
    } else {
        std::cout << "UNKNOWN";
    }
    std::cout << "\n";
    
    // Payload info
    if (stack.payload_len > 0) {
        std::cout << "Payload: " << stack.payload_len << " bytes\n";
        
        // Show first few bytes of payload (hex)
        std::cout << "First bytes: ";
        size_t show_len = std::min(stack.payload_len, (uint16_t)16);
        for (size_t i = 0; i < show_len; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                     << (int)packet.data()[stack.payload_offset + i] << " ";
        }
        std::cout << std::dec << "\n";
        
        // Show printable chars
        std::cout << "Printable: ";
        for (size_t i = 0; i < show_len; ++i) {
            char c = packet.data()[stack.payload_offset + i];
            if (std::isprint(c)) {
                std::cout << c;
            } else {
                std::cout << ".";
            }
        }
        std::cout << "\n";
    }
}

void packet_handler(const Packet& pkt, void* user_data) {
    Packet packet = pkt;
    g_total_packets++;
    
    // Step 1: Parse protocol headers (L2-L4)
    int datalink = *static_cast<int*>(user_data);
    if (!ProtocolParser::parse(packet, datalink)) {
        return;
    }
    
    // Step 2: Identify application protocol (L7)
    IdentificationResult result = g_identifier.identify(packet);
    
    if (result.protocol != ProtocolType::UNKNOWN) {
        g_identified_packets++;
        g_protocol_stats[result.protocol]++;
    }
    
    // Print detailed info for first 10 packets
    if (g_total_packets <= 10) {
        print_protocol_info(packet, result);
    }
    
    // Print progress every 100 packets
    if (g_total_packets % 100 == 0) {
        std::cout << "[INFO] Processed " << g_total_packets << " packets, "
                  << "identified " << g_identified_packets << " ("
                  << (g_total_packets > 0 ? (g_identified_packets * 100 / g_total_packets) : 0) 
                  << "%)\n";
    }
}

void print_statistics() {
    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════════╗\n";
    std::cout << "║   Protocol Identification Statistics      ║\n";
    std::cout << "╚════════════════════════════════════════════╝\n";
    std::cout << "Total packets:      " << g_total_packets << "\n";
    std::cout << "Identified:         " << g_identified_packets << " ("
              << (g_total_packets > 0 ? (g_identified_packets * 100 / g_total_packets) : 0) << "%)\n";
    std::cout << "Unidentified:       " << (g_total_packets - g_identified_packets) << "\n";
    std::cout << "\n";
    
    if (!g_protocol_stats.empty()) {
        std::cout << "Protocol Distribution:\n";
        std::cout << "───────────────────────────────────────────\n";
        
        for (const auto& pair : g_protocol_stats) {
            std::cout << std::setw(15) << std::left << protocol_type_to_string(pair.first)
                     << ": " << std::setw(8) << std::right << pair.second
                     << " (" << std::setw(5) << std::fixed << std::setprecision(2)
                     << (g_total_packets > 0 ? (pair.second * 100.0 / g_total_packets) : 0) << "%)\n";
        }
    }
    std::cout << "\n";
}

int main(int argc, char* argv[]) {
    std::cout << "╔════════════════════════════════════════════╗\n";
    std::cout << "║  NetGuardian Protocol Identification Demo ║\n";
    std::cout << "║  Version " << netguardian::VERSION << "                            ║\n";
    std::cout << "╚════════════════════════════════════════════╝\n\n";

    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <-i interface | -r pcapfile> [options]\n\n";
        std::cout << "Options:\n";
        std::cout << "  -i <interface>  Capture from network interface\n";
        std::cout << "  -r <file>       Read from PCAP file\n";
        std::cout << "  -c <count>      Number of packets to process\n";
        std::cout << "  -v              Verbose output (show all packets)\n";
        std::cout << "\n";
        std::cout << "Examples:\n";
        std::cout << "  " << argv[0] << " -i eth0\n";
        std::cout << "  " << argv[0] << " -r capture.pcap -c 1000\n";
        return 1;
    }

    // Parse arguments
    std::string interface;
    std::string pcap_file;
    int packet_count = 0;
    bool verbose = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) {
            interface = argv[++i];
        } else if (arg == "-r" && i + 1 < argc) {
            pcap_file = argv[++i];
        } else if (arg == "-c" && i + 1 < argc) {
            packet_count = std::atoi(argv[++i]);
        } else if (arg == "-v") {
            verbose = true;
        }
    }

    // Configure capture
    CaptureConfig config;
    if (!interface.empty()) {
        config.interface = interface;
    } else if (!pcap_file.empty()) {
        config.pcap_file = pcap_file;
    } else {
        std::cerr << "[ERROR] No interface or file specified\n";
        return 1;
    }

    // Create capture
    g_capture = std::make_shared<PacketCapture>(config);
    
    if (!g_capture->start()) {
        std::cerr << "[ERROR] Failed to start capture: " << g_capture->get_error() << "\n";
        return 1;
    }

    int datalink = g_capture->get_datalink();
    std::cout << "[INFO] Capture started (datalink type: " << datalink << ")\n";
    std::cout << "[INFO] Protocol identification enabled\n";
    std::cout << "[INFO] Methods: Port-based + DPI (Deep Packet Inspection)\n\n";

    // Set up signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Start processing
    g_capture->set_callback(packet_handler, &datalink);
    g_capture->loop(packet_count);

    // Print final statistics
    print_statistics();

    return 0;
}
