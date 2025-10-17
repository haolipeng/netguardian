#include "core/packet_capture.h"
#include "core/protocol_parser.h"
#include "core/app_protocol_identifier.h"
#include "decoders/ethernet_decoder.h"
#include "decoders/ipv4_decoder.h"
#include "decoders/tcp_decoder.h"
#include "decoders/udp_decoder.h"
#include "decoders/http_decoder.h"
#include "decoders/dns_decoder.h"
#include "core/version.h"

#include <iostream>
#include <iomanip>
#include <signal.h>
#include <atomic>
#include <map>

using namespace netguardian;
using namespace netguardian::core;
using namespace netguardian::decoders;

// 全局变量
std::atomic<bool> g_running(true);
uint64_t g_total_packets = 0;
uint64_t g_decoded_packets = 0;

// 解码器实例
EthernetDecoder g_eth_decoder;
IPv4Decoder g_ipv4_decoder;
TcpDecoder g_tcp_decoder;
UdpDecoder g_udp_decoder;
HttpDecoder g_http_decoder;
DnsDecoder g_dns_decoder;

void signal_handler(int signum) {
    (void)signum;
    g_running = false;
}

void print_separator() {
    std::cout << std::string(70, '=') << "\n";
}

void packet_handler(const Packet& packet, void* user_data) {
    (void)user_data;
    g_total_packets++;

    // 首先进行协议解析（L2-L4）
    Packet mutable_packet = packet;  // 创建可修改的副本
    if (!ProtocolParser::parse(mutable_packet, DLT_EN10MB)) {
        return;
    }

    const auto& stack = mutable_packet.protocol_stack();

    print_separator();
    std::cout << "数据包 #" << g_total_packets << "\n";
    print_separator();

    // === Ethernet 层解码 ===
    if (auto eth_decoded = g_eth_decoder.decode(mutable_packet)) {
        auto eth_data = std::dynamic_pointer_cast<EthernetData>(eth_decoded);
        std::cout << "【以太网层】\n";
        std::cout << "  " << eth_data->to_string() << "\n";
        std::cout << "  源 MAC:      " << EthernetData::mac_to_string(eth_data->src_mac) << "\n";
        std::cout << "  目标 MAC:    " << EthernetData::mac_to_string(eth_data->dst_mac) << "\n";
        std::cout << "  类型:        0x" << std::hex << std::setw(4) << std::setfill('0')
                  << eth_data->ethertype << std::dec << "\n";
        if (eth_data->has_vlan) {
            std::cout << "  VLAN ID:     " << eth_data->vlan_id << "\n";
        }
        std::cout << "\n";
        g_decoded_packets++;
    }

    // === IPv4 层解码 ===
    if (auto ipv4_decoded = g_ipv4_decoder.decode(mutable_packet)) {
        auto ipv4_data = std::dynamic_pointer_cast<IPv4Data>(ipv4_decoded);
        std::cout << "【IP 层】\n";
        std::cout << "  " << ipv4_data->to_string() << "\n";
        std::cout << "  源 IP:       " << ipv4_data->src_ip.to_string() << "\n";
        std::cout << "  目标 IP:     " << ipv4_data->dst_ip.to_string() << "\n";
        std::cout << "  协议:        " << static_cast<int>(ipv4_data->protocol) << "\n";
        std::cout << "  TTL:         " << static_cast<int>(ipv4_data->ttl) << "\n";
        std::cout << "  总长度:      " << ipv4_data->total_length << " 字节\n";
        std::cout << "  头部长度:    " << ipv4_data->header_length() << " 字节\n";
        if (ipv4_data->is_fragmented()) {
            std::cout << "  分片:        是 (offset=" << ipv4_data->fragment_offset << ")\n";
        }
        std::cout << "\n";
    }

    // === TCP 层解码 ===
    if (auto tcp_decoded = g_tcp_decoder.decode(mutable_packet)) {
        auto tcp_data = std::dynamic_pointer_cast<TcpData>(tcp_decoded);
        std::cout << "【TCP 层】\n";
        std::cout << "  " << tcp_data->to_string() << "\n";
        std::cout << "  源端口:      " << tcp_data->src_port << "\n";
        std::cout << "  目标端口:    " << tcp_data->dst_port << "\n";
        std::cout << "  序列号:      " << tcp_data->seq_num << "\n";
        if (tcp_data->flags.ack) {
            std::cout << "  确认号:      " << tcp_data->ack_num << "\n";
        }
        std::cout << "  窗口大小:    " << tcp_data->window_size << "\n";
        std::cout << "  标志:        " << tcp_data->flags.to_string() << "\n";
        std::cout << "  头部长度:    " << tcp_data->header_length() << " 字节\n";
        std::cout << "\n";
    }

    // === UDP 层解码 ===
    if (auto udp_decoded = g_udp_decoder.decode(mutable_packet)) {
        auto udp_data = std::dynamic_pointer_cast<UdpData>(udp_decoded);
        std::cout << "【UDP 层】\n";
        std::cout << "  " << udp_data->to_string() << "\n";
        std::cout << "  源端口:      " << udp_data->src_port << "\n";
        std::cout << "  目标端口:    " << udp_data->dst_port << "\n";
        std::cout << "  长度:        " << udp_data->length << " 字节\n";
        std::cout << "\n";
    }

    // === HTTP 层解码 ===
    if (auto http_decoded = g_http_decoder.decode(mutable_packet)) {
        auto http_data = std::dynamic_pointer_cast<HttpData>(http_decoded);
        std::cout << "【HTTP 层】\n";
        std::cout << "  " << http_data->to_string() << "\n";

        if (http_data->message_type == HttpMessageType::REQUEST) {
            std::cout << "  类型:        请求\n";
            std::cout << "  方法:        " << http_data->method_str << "\n";
            std::cout << "  URI:         " << http_data->uri << "\n";
            std::cout << "  版本:        " << http_data->version << "\n";
        } else if (http_data->message_type == HttpMessageType::RESPONSE) {
            std::cout << "  类型:        响应\n";
            std::cout << "  版本:        " << http_data->version << "\n";
            std::cout << "  状态码:      " << http_data->status_code << "\n";
            std::cout << "  状态消息:    " << http_data->status_message << "\n";
        }

        if (!http_data->headers.empty()) {
            std::cout << "  头部字段:\n";
            for (const auto& [name, value] : http_data->headers) {
                std::cout << "    " << name << ": " << value << "\n";
            }
        }

        if (http_data->has_body && !http_data->body.empty()) {
            std::cout << "  主体预览:    "
                      << http_data->body.substr(0, std::min(size_t(60), http_data->body.size()))
                      << (http_data->body.size() > 60 ? "..." : "") << "\n";
        }
        std::cout << "\n";
    }

    // === DNS 层解码 ===
    if (auto dns_decoded = g_dns_decoder.decode(mutable_packet)) {
        auto dns_data = std::dynamic_pointer_cast<DnsData>(dns_decoded);
        std::cout << "【DNS 层】\n";
        std::cout << "  " << dns_data->to_string() << "\n";
        std::cout << "  事务 ID:     " << dns_data->transaction_id << "\n";
        std::cout << "  类型:        " << (dns_data->is_query ? "查询" : "响应") << "\n";
        std::cout << "  操作码:      " << static_cast<int>(dns_data->opcode) << "\n";

        if (!dns_data->is_query) {
            std::cout << "  响应码:      " << static_cast<int>(dns_data->response_code) << "\n";
        }

        if (!dns_data->queries.empty()) {
            std::cout << "  查询:\n";
            for (const auto& query : dns_data->queries) {
                std::cout << "    " << query.to_string() << "\n";
            }
        }

        if (!dns_data->answers.empty()) {
            std::cout << "  答复:\n";
            for (const auto& answer : dns_data->answers) {
                std::cout << "    " << answer.to_string() << "\n";
            }
        }
        std::cout << "\n";
    }

    std::cout << std::flush;

    // 进度提示（每10个包）
    if (g_total_packets % 10 == 0) {
        std::cerr << "[信息] 已处理 " << g_total_packets << " 个数据包\n";
    }
}

void print_statistics() {
    print_separator();
    std::cout << "【解码统计】\n";
    print_separator();
    std::cout << "总数据包数:        " << g_total_packets << "\n";
    std::cout << "已解码数据包:      " << g_decoded_packets << "\n";
    if (g_total_packets > 0) {
        std::cout << "解码率:            "
                  << std::fixed << std::setprecision(2)
                  << (g_decoded_packets * 100.0 / g_total_packets) << "%\n";
    }
    print_separator();
}

int main(int argc, char* argv[]) {
    std::cout << "╔════════════════════════════════════════════╗\n";
    std::cout << "║    NetGuardian 协议解码器演示程序         ║\n";
    std::cout << "║    版本 " << VERSION << "                          ║\n";
    std::cout << "╚════════════════════════════════════════════╝\n\n";

    if (argc < 2) {
        std::cerr << "[错误] 未指定网络接口或 PCAP 文件\n\n";
        std::cout << "用法: " << argv[0] << " <-i 接口 | -r pcap文件> [选项]\n\n";
        std::cout << "选项:\n";
        std::cout << "  -i <接口>       从网络接口捕获\n";
        std::cout << "  -r <文件>       从 PCAP 文件读取\n";
        std::cout << "  -c <数量>       处理的数据包数量\n";
        std::cout << "\n";
        std::cout << "示例:\n";
        std::cout << "  " << argv[0] << " -i eth0\n";
        std::cout << "  " << argv[0] << " -r capture.pcap -c 100\n";
        return 1;
    }

    // 解析命令行参数
    std::string interface;
    std::string pcap_file;
    int packet_count = 0;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) {
            interface = argv[++i];
        } else if (arg == "-r" && i + 1 < argc) {
            pcap_file = argv[++i];
        } else if (arg == "-c" && i + 1 < argc) {
            packet_count = std::atoi(argv[++i]);
        }
    }

    // 配置捕获
    CaptureConfig config;
    if (!interface.empty()) {
        config.interface = interface;
    } else if (!pcap_file.empty()) {
        config.pcap_file = pcap_file;
    } else {
        std::cerr << "[错误] 必须指定网络接口或 PCAP 文件\n";
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
        return 1;
    }

    std::cout << "[信息] 捕获已启动\n";
    std::cout << "[信息] 数据链路类型: " << capture.get_datalink() << "\n";
    std::cout << "[信息] 按 Ctrl+C 停止...\n\n";

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

    // 打印统计信息
    std::cout << "\n";
    print_statistics();

    return 0;
}
