#include "core/packet_capture.h"
#include "core/protocol_parser.h"
#include "decoders/protocol_headers.h"
#include "flow/flow_table.h"
#include "flow/flow_manager.h"
#include "flow/tcp_state_machine.h"
#include "core/version.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <signal.h>
#include <atomic>
#include <thread>
#include <arpa/inet.h>

using namespace netguardian;
using namespace netguardian::core;
using namespace netguardian::flow;
using namespace netguardian::decoders;

// 全局变量
std::atomic<bool> g_running(true);
FlowTable g_flow_table;
uint64_t g_total_packets = 0;
uint64_t g_exported_flows = 0;
std::ofstream g_export_file;

void signal_handler(int signum) {
    (void)signum;
    g_running = false;
}

void print_separator() {
    std::cout << std::string(80, '=') << "\n";
}

// 流导出回调函数
void flow_export_callback(const Flow& flow) {
    g_exported_flows++;

    // 导出到文件（CSV 格式）
    if (g_export_file.is_open()) {
        const auto& key = flow.key();
        const auto& stats = flow.stats();

        // 格式：流ID,源IP,源端口,目标IP,目标端口,协议,包数,字节数,持续时间,状态
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &key.src_ip, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &key.dst_ip, dst_ip, INET_ADDRSTRLEN);

        g_export_file << flow.flow_id() << ","
                      << src_ip << ","
                      << key.src_port << ","
                      << dst_ip << ","
                      << key.dst_port << ","
                      << static_cast<int>(key.protocol) << ","
                      << stats.packet_count << ","
                      << stats.byte_count << ","
                      << std::fixed << std::setprecision(3) << stats.duration();

        // 如果是 TCP 流，添加状态信息
        if (flow.is_tcp() && flow.has_tcp_state()) {
            g_export_file << "," << tcp_state_to_string(flow.get_tcp_state());
        } else {
            g_export_file << ",N/A";
        }

        g_export_file << "\n";
        g_export_file.flush();
    }

    // 打印到控制台
    std::cout << "[导出] " << flow.to_string() << "\n";
}

// 从数据包中提取五元组
FlowKey extract_flow_key(const Packet& packet) {
    FlowKey key;

    const auto& stack = packet.protocol_stack();

    // 提取 IP 地址
    if (stack.l3_type == ProtocolType::IPV4 &&
        static_cast<size_t>(stack.l3_offset) + sizeof(IPv4Header) <= packet.length()) {

        const IPv4Header* ip_hdr = reinterpret_cast<const IPv4Header*>(
            packet.data() + stack.l3_offset
        );

        key.src_ip = ip_hdr->src_ip;
        key.dst_ip = ip_hdr->dst_ip;
        key.protocol = ip_hdr->protocol;
    }

    // 提取端口（TCP/UDP）
    if (stack.l4_type == ProtocolType::TCP &&
        static_cast<size_t>(stack.l4_offset) + sizeof(TcpHeader) <= packet.length()) {

        const TcpHeader* tcp_hdr = reinterpret_cast<const TcpHeader*>(
            packet.data() + stack.l4_offset
        );

        key.src_port = ntohs(tcp_hdr->src_port);
        key.dst_port = ntohs(tcp_hdr->dst_port);

    } else if (stack.l4_type == ProtocolType::UDP &&
               static_cast<size_t>(stack.l4_offset) + sizeof(UdpHeader) <= packet.length()) {

        const UdpHeader* udp_hdr = reinterpret_cast<const UdpHeader*>(
            packet.data() + stack.l4_offset
        );

        key.src_port = ntohs(udp_hdr->src_port);
        key.dst_port = ntohs(udp_hdr->dst_port);
    }

    return key;
}

void packet_handler(const Packet& packet, void* user_data) {
    (void)user_data;
    g_total_packets++;

    // 协议解析
    Packet mutable_packet = packet;
    if (!ProtocolParser::parse(mutable_packet, DLT_EN10MB)) {
        return;
    }

    const auto& stack = mutable_packet.protocol_stack();

    // 只处理 TCP 和 UDP
    if (stack.l4_type != ProtocolType::TCP && stack.l4_type != ProtocolType::UDP) {
        return;
    }

    // 提取五元组
    FlowKey key = extract_flow_key(mutable_packet);

    // 更新流表
    g_flow_table.update_flow(key, static_cast<uint32_t>(mutable_packet.length()));

    // 如果是 TCP 包，处理 TCP 状态机
    if (stack.l4_type == ProtocolType::TCP &&
        static_cast<size_t>(stack.l4_offset) + sizeof(TcpHeader) <= mutable_packet.length()) {

        const TcpHeader* tcp_hdr = reinterpret_cast<const TcpHeader*>(
            mutable_packet.data() + stack.l4_offset
        );

        // 提取 TCP 标志位
        TcpFlags flags = TcpFlags::from_header(tcp_hdr);

        // 获取或创建流
        auto flow = g_flow_table.get_or_create_flow(key);
        if (flow) {
            // 判断是否是发起方的数据包
            bool is_initiator = (flow->get_direction(key) == FlowDirection::FORWARD);

            // 处理 TCP 数据包（更新状态机）
            flow->process_tcp_packet(
                flags,
                ntohl(tcp_hdr->seq_num),
                ntohl(tcp_hdr->ack_num),
                is_initiator
            );
        }
    }
}

void print_flow_table() {
    print_separator();
    std::cout << "【流表信息】\n";
    print_separator();

    auto flows = g_flow_table.get_all_flows();

    if (flows.empty()) {
        std::cout << "没有活跃的流\n";
        return;
    }

    std::cout << "活跃流数量: " << flows.size() << "\n\n";

    // 按流 ID 排序
    std::sort(flows.begin(), flows.end(),
        [](const FlowTable::FlowPtr& a, const FlowTable::FlowPtr& b) {
            return a->flow_id() < b->flow_id();
        });

    // 打印每个流的详细信息
    for (const auto& flow : flows) {
        std::cout << flow->to_string() << "\n";

        // 如果是 TCP 流，显示额外的连接信息
        if (flow->is_tcp() && flow->has_tcp_state()) {
            const auto* conn_info = flow->get_tcp_connection_info();
            if (conn_info) {
                std::cout << "    ├─ 握手: "
                          << (conn_info->syn_seen ? "SYN✓ " : "SYN✗ ")
                          << (conn_info->syn_ack_seen ? "SYN-ACK✓ " : "SYN-ACK✗ ")
                          << (conn_info->handshake_complete ? "完成✓" : "未完成")
                          << "\n";

                std::cout << "    ├─ 挥手: "
                          << (conn_info->fin_from_initiator ? "发起方FIN✓ " : "发起方FIN✗ ")
                          << (conn_info->fin_from_responder ? "响应方FIN✓ " : "响应方FIN✗ ")
                          << (conn_info->shutdown_complete ? "完成✓" : "")
                          << "\n";

                std::cout << "    └─ 异常: "
                          << "RST=" << (conn_info->rst_seen ? "是" : "否")
                          << ", 重传=" << conn_info->retransmissions
                          << ", 乱序=" << conn_info->out_of_order
                          << "\n";
            }
        }
    }

    std::cout << "\n";
}

void print_statistics() {
    print_separator();
    std::cout << "【统计信息】\n";
    print_separator();

    auto stats = g_flow_table.get_stats();

    std::cout << "总数据包数:        " << g_total_packets << "\n";
    std::cout << "总流数 (历史):     " << stats.total_flows << "\n";
    std::cout << "活跃流数:          " << stats.active_flows << "\n";
    std::cout << "导出流数:          " << g_exported_flows << "\n";
    std::cout << "总字节数:          " << stats.total_bytes << "\n";

    if (stats.total_bytes >= 1024 * 1024) {
        std::cout << "                  (" << std::fixed << std::setprecision(2)
                  << (stats.total_bytes / 1024.0 / 1024.0) << " MB)\n";
    } else if (stats.total_bytes >= 1024) {
        std::cout << "                  (" << std::fixed << std::setprecision(2)
                  << (stats.total_bytes / 1024.0) << " KB)\n";
    }

    std::cout << "\n";
}

int main(int argc, char* argv[]) {
    std::cout << "╔════════════════════════════════════════════╗\n";
    std::cout << "║    NetGuardian 流管理演示程序             ║\n";
    std::cout << "║    版本 " << VERSION << "                          ║\n";
    std::cout << "╚════════════════════════════════════════════╝\n\n";

    if (argc < 2) {
        std::cerr << "[错误] 未指定网络接口或 PCAP 文件\n\n";
        std::cout << "用法: " << argv[0] << " <-i 接口 | -r pcap文件> [选项]\n\n";
        std::cout << "选项:\n";
        std::cout << "  -i <接口>       从网络接口捕获\n";
        std::cout << "  -r <文件>       从 PCAP 文件读取\n";
        std::cout << "  -c <数量>       处理的数据包数量\n";
        std::cout << "  -o <文件>       流导出文件路径 (CSV 格式)\n";
        std::cout << "\n";
        std::cout << "示例:\n";
        std::cout << "  " << argv[0] << " -i eth0 -o flows.csv\n";
        std::cout << "  " << argv[0] << " -r capture.pcap -c 1000 -o flows.csv\n";
        return 1;
    }

    // 解析命令行参数
    std::string interface;
    std::string pcap_file;
    std::string export_file = "flows.csv";
    int packet_count = 0;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) {
            interface = argv[++i];
        } else if (arg == "-r" && i + 1 < argc) {
            pcap_file = argv[++i];
        } else if (arg == "-c" && i + 1 < argc) {
            packet_count = std::atoi(argv[++i]);
        } else if (arg == "-o" && i + 1 < argc) {
            export_file = argv[++i];
        }
    }

    // 打开导出文件
    g_export_file.open(export_file);
    if (!g_export_file.is_open()) {
        std::cerr << "[错误] 无法打开导出文件: " << export_file << "\n";
        return 1;
    }

    // 写入 CSV 头部
    g_export_file << "FlowID,SourceIP,SourcePort,DestIP,DestPort,Protocol,"
                  << "Packets,Bytes,Duration,State\n";

    std::cout << "[信息] 流导出文件: " << export_file << "\n\n";

    // 配置流超时（用于测试，设置较短的超时时间）
    FlowTimeoutConfig timeout_config;
    timeout_config.tcp_established_timeout = 3600;  // 1小时
    timeout_config.tcp_closing_timeout = 120;       // 2分钟
    timeout_config.tcp_closed_timeout = 5;          // 5秒（快速清理已关闭连接）
    timeout_config.tcp_unknown_timeout = 300;       // 5分钟
    timeout_config.udp_timeout = 30;                // 30秒
    timeout_config.other_timeout = 30;              // 30秒

    // 创建流管理器
    FlowManager flow_manager(g_flow_table, timeout_config);
    flow_manager.set_export_callback(flow_export_callback);

    // 配置捕获
    CaptureConfig config;
    if (!interface.empty()) {
        config.interface = interface;
    } else if (!pcap_file.empty()) {
        config.pcap_file = pcap_file;
    } else {
        std::cerr << "[错误] 必须指定网络接口或 PCAP 文件\n";
        g_export_file.close();
        return 1;
    }

    config.snaplen = 65535;
    config.promiscuous = true;
    config.timeout_ms = 1000;

    // 创建捕获器
    PacketCapture capture(config);

    // 注册信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 设置回调
    capture.set_callback(packet_handler);

    // 启动捕获
    if (!capture.start()) {
        std::cerr << "[错误] 启动捕获失败: " << capture.get_error() << "\n";
        g_export_file.close();
        return 1;
    }

    std::cout << "[信息] 捕获已启动\n";
    std::cout << "[信息] 数据链路类型: " << capture.get_datalink() << "\n";
    std::cout << "[信息] 按 Ctrl+C 停止...\n\n";

    // 启动周期性清理线程
    std::thread cleanup_thread([&]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(5));

            // 清理超时的流
            size_t removed = flow_manager.cleanup_expired_flows();
            if (removed > 0) {
                std::cout << "[清理] 删除了 " << removed << " 个超时的流\n";
            }
        }
    });

    // 开始捕获循环
    while (g_running) {
        int result = capture.loop(packet_count > 0 ? packet_count : 10);
        if (result < 0) {
            std::cerr << "[错误] 捕获错误: " << capture.get_error() << "\n";
            break;
        }

        if (packet_count > 0 && g_total_packets >= static_cast<uint64_t>(packet_count)) {
            break;
        }
    }

    // 停止捕获
    capture.stop();

    // 等待清理线程结束
    g_running = false;
    if (cleanup_thread.joinable()) {
        cleanup_thread.join();
    }

    // 导出所有剩余的流
    std::cout << "\n[信息] 导出所有剩余的流...\n";
    flow_manager.export_all_flows();

    // 打印流表和统计信息
    std::cout << "\n";
    print_flow_table();
    print_statistics();

    // 关闭导出文件
    g_export_file.close();
    std::cout << "[信息] 流导出完成: " << export_file << "\n";

    return 0;
}
