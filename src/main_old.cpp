#include "core/version.h"
#include "core/packet.h"
#include "core/packet_capture.h"
#include "core/detection_engine.h"
#include <iostream>
#include <cstdlib>
#include <csignal>
#include <atomic>
#include <thread>
#include <iomanip>
#include <chrono>

using namespace netguardian;
using namespace netguardian::core;

// ============================================================================
// 全局变量
// ============================================================================

std::atomic<bool> g_running(true);
DetectionEngine* g_engine = nullptr;
PacketCapture* g_capture = nullptr;

// 统计报告间隔（秒）
int g_stats_interval = 60;

// ============================================================================
// 信号处理
// ============================================================================

void signal_handler(int signum) {
    (void)signum;
    std::cout << "\n[INFO] Received shutdown signal, stopping gracefully...\n";
    g_running = false;
}

// ============================================================================
// 打印函数
// ============================================================================

void print_banner() {
    std::cout << "╔════════════════════════════════════════════════════════╗\n";
    std::cout << "║              NetGuardian v" << VERSION << "                        ║\n";
    std::cout << "║       Network Security Monitoring System               ║\n";
    std::cout << "╚════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
}

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n\n";
    std::cout << "Basic Options:\n";
    std::cout << "  -i <interface>    Network interface to monitor\n";
    std::cout << "  -r <file>         Read packets from pcap file\n";
    std::cout << "  -c <count>        Number of packets to process (0 = unlimited)\n";
    std::cout << "  -v, --verbose     Verbose output\n";
    std::cout << "  -h, --help        Show this help message\n";
    std::cout << "  --version         Show version information\n\n";
    std::cout << "Advanced Options:\n";
    std::cout << "  -R <path>         Rules directory path\n";
    std::cout << "  -A <file>         Alert output file\n";
    std::cout << "  -s <seconds>      Statistics report interval (default: 60)\n";
    std::cout << "  -f <filter>       BPF filter expression\n";
    std::cout << "  --no-flow         Disable flow tracking\n";
    std::cout << "  --no-reassembly   Disable reassembly engines\n";
    std::cout << "  --no-anomaly      Disable anomaly detection\n";
    std::cout << "\n";
    std::cout << "Examples:\n";
    std::cout << "  " << prog << " -i eth0 -R /etc/netguardian/rules\n";
    std::cout << "  " << prog << " -r capture.pcap -A alerts.json -s 10\n";
    std::cout << "  " << prog << " -i eth0 -f \"tcp port 80\"\n";
    std::cout << "\n";
}

void print_separator(char ch = '━') {
    std::cout << std::string(60, ch) << "\n";
}

// ============================================================================
// 统计报告
// ============================================================================

void print_statistics_header() {
    print_separator();
    std::cout << "Statistics Report\n";
    print_separator();
}

void print_statistics(const DetectionEngineStats& stats, const flow::FlowTableStats& flow_stats) {
    // 数据包统计
    std::cout << "Packets:        " << std::setw(12) << stats.total_packets.load();
    if (stats.total_packets > 0) {
        double drop_rate = (double)stats.dropped_packets.load() / stats.total_packets.load() * 100;
        std::cout << "  (dropped: " << std::fixed << std::setprecision(2) << drop_rate << "%)";
    }
    std::cout << "\n";

    // 字节统计
    uint64_t total_bytes = stats.total_bytes.load();
    std::cout << "Bytes:          " << std::setw(12) << total_bytes;
    if (total_bytes >= 1024 * 1024 * 1024) {
        std::cout << "  (" << std::fixed << std::setprecision(2)
                  << (total_bytes / 1024.0 / 1024.0 / 1024.0) << " GB)";
    } else if (total_bytes >= 1024 * 1024) {
        std::cout << "  (" << std::fixed << std::setprecision(2)
                  << (total_bytes / 1024.0 / 1024.0) << " MB)";
    } else if (total_bytes >= 1024) {
        std::cout << "  (" << std::fixed << std::setprecision(2)
                  << (total_bytes / 1024.0) << " KB)";
    }
    std::cout << "\n";

    // 流统计
    std::cout << "Flows:          " << std::setw(12) << flow_stats.active_flows
              << " active / " << flow_stats.total_flows << " total\n";

    // 协议分布
    std::cout << "\nProtocol Distribution:\n";
    std::cout << "  IPv4:         " << std::setw(12) << stats.ipv4_packets.load() << "\n";
    std::cout << "  IPv6:         " << std::setw(12) << stats.ipv6_packets.load() << "\n";
    std::cout << "  TCP:          " << std::setw(12) << stats.tcp_packets.load() << "\n";
    std::cout << "  UDP:          " << std::setw(12) << stats.udp_packets.load() << "\n";
    std::cout << "  HTTP:         " << std::setw(12) << stats.http_packets.load() << "\n";
    std::cout << "  DNS:          " << std::setw(12) << stats.dns_packets.load() << "\n";

    // 检测统计
    std::cout << "\nDetection Statistics:\n";
    std::cout << "  Rules matched:" << std::setw(12) << stats.rules_matched.load() << "\n";
    std::cout << "  Anomalies:    " << std::setw(12) << stats.anomalies_detected.load() << "\n";
    std::cout << "  Alerts:       " << std::setw(12) << stats.total_alerts.load();
    if (stats.alerts_suppressed > 0) {
        std::cout << "  (suppressed: " << stats.alerts_suppressed.load() << ")";
    }
    std::cout << "\n";

    print_separator();
    std::cout << "\n";
}

// ============================================================================
// 统计线程
// ============================================================================

void statistics_thread() {
    auto last_report_time = std::chrono::steady_clock::now();

    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_report_time).count();

        if (elapsed >= g_stats_interval) {
            if (g_engine) {
                print_statistics_header();
                print_statistics(g_engine->get_stats(), g_engine->get_flow_stats());
            }
            last_report_time = now;
        }
    }
}

// ============================================================================
// 数据包回调
// ============================================================================

void packet_callback(const Packet& packet, void* user_data) {
    (void)user_data;

    if (g_engine && g_running) {
        g_engine->process_packet(packet);
    }
}

// ============================================================================
// 主函数
// ============================================================================

int main(int argc, char* argv[]) {
    print_banner();

    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // 解析命令行参数
    std::string interface;
    std::string pcap_file;
    std::string rules_path;
    std::string alert_file;
    std::string bpf_filter;
    int packet_count = 0;
    bool verbose = false;
    bool enable_flow = true;
    bool enable_reassembly = true;
    bool enable_anomaly = true;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        else if (arg == "--version") {
            std::cout << "NetGuardian version " << VERSION << "\n";
            return EXIT_SUCCESS;
        }
        else if (arg == "-i" && i + 1 < argc) {
            interface = argv[++i];
        }
        else if (arg == "-r" && i + 1 < argc) {
            pcap_file = argv[++i];
        }
        else if (arg == "-c" && i + 1 < argc) {
            packet_count = std::atoi(argv[++i]);
        }
        else if (arg == "-R" && i + 1 < argc) {
            rules_path = argv[++i];
        }
        else if (arg == "-A" && i + 1 < argc) {
            alert_file = argv[++i];
        }
        else if (arg == "-s" && i + 1 < argc) {
            g_stats_interval = std::atoi(argv[++i]);
        }
        else if (arg == "-f" && i + 1 < argc) {
            bpf_filter = argv[++i];
        }
        else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        }
        else if (arg == "--no-flow") {
            enable_flow = false;
        }
        else if (arg == "--no-reassembly") {
            enable_reassembly = false;
        }
        else if (arg == "--no-anomaly") {
            enable_anomaly = false;
        }
    }

    // 配置检测引擎
    DetectionEngineConfig config;
    config.rules_path = rules_path;
    config.alert_console_output = true;
    config.alert_file_output = !alert_file.empty();
    config.alert_output_path = alert_file;
    config.alert_output_format = alerts::FileAlertOutput::FileFormat::JSON;
    config.enable_tcp_reassembly = enable_reassembly;
    config.enable_ip_reassembly = enable_reassembly;
    config.enable_http_parser = true;
    config.enable_dns_parser = true;
    config.enable_dns_anomaly_detection = enable_anomaly;

    // 创建检测引擎
    std::cout << "[INFO] Creating detection engine...\n";
    DetectionEngine engine(config);
    g_engine = &engine;

    // 初始化检测引擎
    if (!engine.initialize()) {
        std::cerr << "[ERROR] Failed to initialize detection engine\n";
        return EXIT_FAILURE;
    }

    // 配置数据包捕获
    CaptureConfig capture_config;
    if (!interface.empty()) {
        capture_config.interface = interface;
        std::cout << "[INFO] Capture mode: Live capture on " << interface << "\n";
    } else if (!pcap_file.empty()) {
        capture_config.pcap_file = pcap_file;
        std::cout << "[INFO] Capture mode: Offline from " << pcap_file << "\n";
    } else {
        std::cerr << "[ERROR] Must specify either -i (interface) or -r (pcap file)\n";
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    capture_config.snaplen = 65535;
    capture_config.promiscuous = true;
    capture_config.timeout_ms = 1000;
    capture_config.filter = bpf_filter;

    // 创建捕获器
    std::cout << "[INFO] Creating packet capture...\n";
    PacketCapture capture(capture_config);
    g_capture = &capture;

    // 注册信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 设置回调
    capture.set_callback(packet_callback);

    // 启动捕获
    if (!capture.start()) {
        std::cerr << "[ERROR] Failed to start capture: " << capture.get_error() << "\n";
        return EXIT_FAILURE;
    }

    std::cout << "[INFO] Packet capture started\n";
    std::cout << "[INFO] Datalink type: " << capture.get_datalink() << "\n";
    if (!bpf_filter.empty()) {
        std::cout << "[INFO] BPF filter: " << bpf_filter << "\n";
    }
    std::cout << "[INFO] Press Ctrl+C to stop...\n\n";

    // 启动引擎
    engine.start();

    // 启动统计线程
    std::thread stats_thread;
    if (g_stats_interval > 0) {
        stats_thread = std::thread(statistics_thread);
    }

    // 捕获循环
    uint64_t processed = 0;
    while (g_running) {
        int batch = (packet_count > 0) ? std::min(100, packet_count - (int)processed) : 100;
        if (batch <= 0) break;

        int result = capture.loop(batch);
        if (result < 0) {
            std::cerr << "[ERROR] Capture error: " << capture.get_error() << "\n";
            break;
        }

        if (result == 0) {
            // 没有更多数据包（可能是文件结束）
            if (!pcap_file.empty()) {
                std::cout << "[INFO] Reached end of pcap file\n";
                break;
            }
        }

        processed += result;

        if (packet_count > 0 && processed >= (uint64_t)packet_count) {
            std::cout << "[INFO] Processed " << processed << " packets, stopping...\n";
            break;
        }
    }

    // 停止捕获
    capture.stop();
    std::cout << "\n[INFO] Packet capture stopped\n";

    // 停止引擎（导出流、刷新缓冲区）
    std::cout << "[INFO] Flushing detection engine...\n";
    engine.stop();

    // 等待统计线程结束
    g_running = false;
    if (stats_thread.joinable()) {
        stats_thread.join();
    }

    // 打印最终统计
    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════════════════════╗\n";
    std::cout << "║              Final Statistics Report                   ║\n";
    std::cout << "╚════════════════════════════════════════════════════════╝\n";
    print_statistics(engine.get_stats(), engine.get_flow_stats());

    std::cout << "[INFO] NetGuardian stopped.\n";

    return EXIT_SUCCESS;
}
