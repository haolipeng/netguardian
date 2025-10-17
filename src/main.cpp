#include "core/version.h"
#include "core/packet.h"
#include "core/flow.h"
#include <iostream>
#include <cstdlib>

void print_banner() {
    std::cout << "╔════════════════════════════════════════╗\n";
    std::cout << "║         NetGuardian v" << netguardian::VERSION << "          ║\n";
    std::cout << "║  Network Security Monitoring System    ║\n";
    std::cout << "╚════════════════════════════════════════╝\n";
    std::cout << "\n";
}

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -i <interface>    Network interface to monitor\n";
    std::cout << "  -r <file>         Read packets from pcap file\n";
    std::cout << "  -c <config>       Configuration file path\n";
    std::cout << "  -v                Verbose output\n";
    std::cout << "  -h, --help        Show this help message\n";
    std::cout << "  --version         Show version information\n";
    std::cout << "\n";
    std::cout << "Examples:\n";
    std::cout << "  " << prog << " -i eth0 -c /etc/netguardian/netguardian.conf\n";
    std::cout << "  " << prog << " -r capture.pcap\n";
    std::cout << "\n";
}

int main(int argc, char* argv[]) {
    print_banner();

    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Parse command line arguments
    std::string interface;
    std::string pcap_file;
    std::string config_file;
    bool verbose = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        else if (arg == "--version") {
            std::cout << "NetGuardian version " << netguardian::VERSION << "\n";
            return EXIT_SUCCESS;
        }
        else if (arg == "-i" && i + 1 < argc) {
            interface = argv[++i];
        }
        else if (arg == "-r" && i + 1 < argc) {
            pcap_file = argv[++i];
        }
        else if (arg == "-c" && i + 1 < argc) {
            config_file = argv[++i];
        }
        else if (arg == "-v") {
            verbose = true;
        }
    }

    // Placeholder for actual implementation
    std::cout << "NetGuardian is starting...\n";

    if (!interface.empty()) {
        std::cout << "Monitoring interface: " << interface << "\n";
    }
    if (!pcap_file.empty()) {
        std::cout << "Reading from pcap: " << pcap_file << "\n";
    }
    if (!config_file.empty()) {
        std::cout << "Using config: " << config_file << "\n";
    }

    std::cout << "\n[INFO] Core modules initialized\n";

#ifdef ENABLE_SNORT_INTEGRATION
    std::cout << "[INFO] Snort detection engine: ENABLED\n";
#else
    std::cout << "[INFO] Snort detection engine: DISABLED\n";
#endif

#ifdef ENABLE_ZEEK_INTEGRATION
    std::cout << "[INFO] Zeek protocol analyzers: ENABLED\n";
#else
    std::cout << "[INFO] Zeek protocol analyzers: DISABLED\n";
#endif

    std::cout << "\n[INFO] NetGuardian is ready!\n";
    std::cout << "[INFO] Press Ctrl+C to stop...\n";

    // TODO: Implement actual packet processing loop
    std::cout << "\n[WARN] Full implementation in progress...\n";
    std::cout << "[INFO] This is a framework demonstration.\n";

    return EXIT_SUCCESS;
}
