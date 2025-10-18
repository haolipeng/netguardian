#include "core/detection_engine.h"
#include "core/protocol_parser.h"
#include "decoders/protocol_headers.h"
#include "decoders/packet_info.h"
#include "alerts/alert_output.h"
#include <iostream>
#include <arpa/inet.h>

namespace netguardian {
namespace core {

// ============================================================================
// 构造和析构
// ============================================================================

DetectionEngine::DetectionEngine(const DetectionEngineConfig& config)
    : config_(config)
{
}

DetectionEngine::~DetectionEngine() {
    stop();
}

// ============================================================================
// 初始化
// ============================================================================

bool DetectionEngine::initialize() {
    if (initialized_) {
        return true;
    }

    std::cout << "[INFO] Initializing detection engine...\n";

    try {
        // 初始化解码器
        eth_decoder_ = std::make_unique<decoders::EthernetDecoder>();
        ipv4_decoder_ = std::make_unique<decoders::IPv4Decoder>();
        tcp_decoder_ = std::make_unique<decoders::TcpDecoder>();
        udp_decoder_ = std::make_unique<decoders::UdpDecoder>();
        std::cout << "  ✓ Protocol decoders initialized\n";

        // 初始化流管理
        flow_table_ = std::make_unique<flow::FlowTable>();
        flow_manager_ = std::make_unique<flow::FlowManager>(*flow_table_, config_.flow_timeout);
        std::cout << "  ✓ Flow tracker initialized (max " << config_.max_flows << " flows)\n";

        // 初始化重组器
        if (config_.enable_tcp_reassembly) {
            tcp_reasm_ = std::make_unique<reassembly::TcpReassembler>();
        }
        if (config_.enable_ip_reassembly) {
            ipv4_reasm_ = std::make_unique<reassembly::Ipv4Reassembler>(config_.ip_reasm_timeout);
            ipv6_reasm_ = std::make_unique<reassembly::Ipv6Reassembler>(config_.ip_reasm_timeout);
        }
        std::cout << "  ✓ Reassembly engines initialized\n";

        // 初始化L7解析器
        if (config_.enable_http_parser) {
            http_parser_ = std::make_unique<decoders::HttpParser>();
        }
        if (config_.enable_dns_parser) {
            dns_parser_ = std::make_unique<decoders::DnsParser>();
        }

        // 初始化异常检测
        if (config_.enable_dns_anomaly_detection) {
            dns_anomaly_ = std::make_unique<decoders::DnsAnomalyDetector>(config_.dns_anomaly_config);
        }

        // 初始化规则引擎
        rule_manager_ = std::make_unique<rules::RuleManager>();
        if (!config_.rules_path.empty()) {
            if (!load_rules(config_.rules_path)) {
                std::cerr << "  [WARN] Failed to load rules from " << config_.rules_path << "\n";
            }
        }

        // 初始化告警系统
        alert_generator_ = std::make_unique<alerts::AlertGenerator>();
        alert_manager_ = std::make_unique<alerts::AlertManager>();
        alert_manager_->set_deduplication_config(config_.alert_dedup_config);

        // 添加告警输出
        if (config_.alert_console_output) {
            auto console_output = std::make_shared<alerts::ConsoleAlertOutput>(
                alerts::ConsoleAlertOutput::ColorMode::BASIC
            );
            alert_manager_->add_output(console_output);
        }

        if (config_.alert_file_output && !config_.alert_output_path.empty()) {
            auto file_output = std::make_shared<alerts::FileAlertOutput>(
                config_.alert_output_path,
                config_.alert_output_format
            );
            alert_manager_->add_output(file_output);
        }

        std::cout << "  ✓ Alert system initialized\n";

        initialized_ = true;
        std::cout << "[INFO] Detection engine initialized successfully\n\n";
        return true;

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Failed to initialize detection engine: " << e.what() << "\n";
        return false;
    }
}

// ============================================================================
// 控制方法
// ============================================================================

void DetectionEngine::start() {
    if (!initialized_) {
        if (!initialize()) {
            throw std::runtime_error("Detection engine initialization failed");
        }
    }
    running_ = true;
}

void DetectionEngine::stop() {
    running_ = false;
    flush();
}

void DetectionEngine::flush() {
    if (flow_manager_) {
        flow_manager_->export_all_flows();
    }
    if (alert_manager_) {
        alert_manager_->cleanup_dedup_records();
    }
}

// ============================================================================
// 规则管理
// ============================================================================

bool DetectionEngine::load_rules(const std::string& rules_path) {
    if (!rule_manager_) {
        return false;
    }

    // 这里简化处理，实际应该扫描目录加载所有规则文件
    // TODO: 实现完整的规则加载逻辑
    std::cout << "  [INFO] Loading rules from " << rules_path << "...\n";

    // 假设加载成功
    size_t count = get_rule_count();
    if (count > 0) {
        std::cout << "  ✓ Rule engine initialized (" << count << " rules loaded)\n";
        return true;
    } else {
        std::cout << "  [WARN] No rules loaded\n";
        return false;
    }
}

size_t DetectionEngine::get_rule_count() const {
    if (!rule_manager_) {
        return 0;
    }
    return rule_manager_->size();
}

flow::FlowTableStats DetectionEngine::get_flow_stats() const {
    if (flow_table_) {
        return flow_table_->get_stats();
    }
    return flow::FlowTableStats();
}

// ============================================================================
// 数据包处理主流程
// ============================================================================

void DetectionEngine::process_packet(const Packet& packet) {
    if (!running_ || !initialized_) {
        return;
    }

    // 更新统计
    stats_.total_packets++;
    stats_.total_bytes += packet.length();

    // 创建可修改的副本（用于协议解析）
    Packet mutable_packet = packet;

    // 1. 协议解析 (L2-L4)
    if (!parse_protocols(mutable_packet)) {
        stats_.dropped_packets++;
        return;
    }

    // 2. 流跟踪
    process_flow(mutable_packet);

    // 3. 重组
    if (config_.enable_tcp_reassembly || config_.enable_ip_reassembly) {
        process_reassembly(mutable_packet);
    }

    // 4. L7 深度解析 (包含异常检测)
    process_l7_parsing(mutable_packet);

    // 5. 检测（规则匹配）
    process_detection(mutable_packet);
}

// ============================================================================
// 协议解析
// ============================================================================

bool DetectionEngine::parse_protocols(Packet& packet) {
    // 使用 ProtocolParser 进行完整协议栈解析
    if (!ProtocolParser::parse(packet, DLT_EN10MB)) {
        return false;
    }

    const auto& stack = packet.protocol_stack();

    // 更新协议统计
    if (stack.l2_type == ProtocolType::ETHERNET) {
        stats_.ethernet_packets++;
    }
    if (stack.l3_type == ProtocolType::IPV4) {
        stats_.ipv4_packets++;
    } else if (stack.l3_type == ProtocolType::IPV6) {
        stats_.ipv6_packets++;
    }
    if (stack.l4_type == ProtocolType::TCP) {
        stats_.tcp_packets++;
    } else if (stack.l4_type == ProtocolType::UDP) {
        stats_.udp_packets++;
    }

    return true;
}

// ============================================================================
// 流处理
// ============================================================================

flow::FlowKey DetectionEngine::extract_flow_key(const Packet& packet) const {
    flow::FlowKey key;
    const auto& stack = packet.protocol_stack();

    // 提取 IP 地址
    if (stack.l3_type == ProtocolType::IPV4 &&
        static_cast<size_t>(stack.l3_offset) + sizeof(decoders::IPv4Header) <= packet.length()) {

        const auto* ip_hdr = reinterpret_cast<const decoders::IPv4Header*>(
            packet.data() + stack.l3_offset
        );

        key.src_ip = ip_hdr->src_ip;
        key.dst_ip = ip_hdr->dst_ip;
        key.protocol = ip_hdr->protocol;
    }

    // 提取端口
    if (stack.l4_type == ProtocolType::TCP &&
        static_cast<size_t>(stack.l4_offset) + sizeof(decoders::TcpHeader) <= packet.length()) {

        const auto* tcp_hdr = reinterpret_cast<const decoders::TcpHeader*>(
            packet.data() + stack.l4_offset
        );

        key.src_port = ntohs(tcp_hdr->src_port);
        key.dst_port = ntohs(tcp_hdr->dst_port);

    } else if (stack.l4_type == ProtocolType::UDP &&
               static_cast<size_t>(stack.l4_offset) + sizeof(decoders::UdpHeader) <= packet.length()) {

        const auto* udp_hdr = reinterpret_cast<const decoders::UdpHeader*>(
            packet.data() + stack.l4_offset
        );

        key.src_port = ntohs(udp_hdr->src_port);
        key.dst_port = ntohs(udp_hdr->dst_port);
    }

    return key;
}

void DetectionEngine::process_flow(Packet& packet) {
    if (!flow_table_) {
        return;
    }

    const auto& stack = packet.protocol_stack();

    // 只处理 TCP/UDP
    if (stack.l4_type != ProtocolType::TCP && stack.l4_type != ProtocolType::UDP) {
        return;
    }

    flow::FlowKey key = extract_flow_key(packet);

    // 更新流表
    flow_table_->update_flow(key, static_cast<uint32_t>(packet.length()));

    // TCP 状态处理
    if (stack.l4_type == ProtocolType::TCP &&
        static_cast<size_t>(stack.l4_offset) + sizeof(decoders::TcpHeader) <= packet.length()) {

        const auto* tcp_hdr = reinterpret_cast<const decoders::TcpHeader*>(
            packet.data() + stack.l4_offset
        );

        auto flow = flow_table_->get_or_create_flow(key);
        if (flow) {
            flow::TcpFlags flags = flow::TcpFlags::from_header(tcp_hdr);
            bool is_initiator = (flow->get_direction(key) == flow::FlowDirection::FORWARD);

            flow->process_tcp_packet(
                flags,
                ntohl(tcp_hdr->seq_num),
                ntohl(tcp_hdr->ack_num),
                is_initiator
            );
        }
    }

    // 更新流统计
    stats_.active_flows = flow_table_->get_stats().active_flows;
    stats_.total_flows = flow_table_->get_stats().total_flows;
}

// ============================================================================
// 重组处理
// ============================================================================

void DetectionEngine::process_reassembly(Packet& packet) {
    const auto& stack = packet.protocol_stack();

    // TCP 重组
    if (config_.enable_tcp_reassembly && tcp_reasm_ &&
        stack.l4_type == ProtocolType::TCP &&
        static_cast<size_t>(stack.l4_offset) + sizeof(decoders::TcpHeader) <= packet.length()) {

        // TODO: 实现 TCP 重组集成
        // tcp_reasm_->add_segment(...);
    }

    // IP 分片重组
    if (config_.enable_ip_reassembly) {
        // IPv4
        if (ipv4_reasm_ && stack.l3_type == ProtocolType::IPV4) {
            // TODO: 实现 IPv4 分片重组集成
        }
        // IPv6
        if (ipv6_reasm_ && stack.l3_type == ProtocolType::IPV6) {
            // TODO: 实现 IPv6 分片重组集成
        }
    }
}

// ============================================================================
// L7 深度解析
// ============================================================================

void DetectionEngine::process_l7_parsing(Packet& packet) {
    const auto& stack = packet.protocol_stack();

    // 只处理有负载的包
    if (stack.payload_len == 0) {
        return;
    }

    const uint8_t* payload = packet.data() + stack.payload_offset;
    size_t payload_len = stack.payload_len;

    // HTTP 解析
    if (config_.enable_http_parser && http_parser_ && stack.l4_type == ProtocolType::TCP) {
        // 检查是否是 HTTP 端口
        flow::FlowKey key = extract_flow_key(packet);
        if (key.dst_port == 80 || key.dst_port == 8080 || key.src_port == 80 || key.src_port == 8080) {
            decoders::HttpRequest request;
            if (decoders::HttpParser::parse_request(payload, payload_len, request) > 0) {
                stats_.http_packets++;
                // HTTP 请求成功解析
                // TODO: 可以将解析结果用于规则匹配
            }
        }
    }

    // DNS 解析
    if (config_.enable_dns_parser && dns_parser_ && stack.l4_type == ProtocolType::UDP) {
        // 检查是否是 DNS 端口
        flow::FlowKey key = extract_flow_key(packet);
        if (key.dst_port == 53 || key.src_port == 53) {
            decoders::DnsMessage message;
            if (decoders::DnsParser::parse_message(payload, payload_len, message) > 0) {
                stats_.dns_packets++;

                // 立即进行 DNS 异常检测
                if (config_.enable_dns_anomaly_detection && dns_anomaly_) {
                    auto anomalies = dns_anomaly_->detect(message);
                    if (!anomalies.empty()) {
                        stats_.anomalies_detected += anomalies.size();
                        for (const auto& anomaly : anomalies) {
                            std::cout << "[ANOMALY] " << anomaly.to_string() << "\n";
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// 检测处理
// ============================================================================

void DetectionEngine::process_detection(Packet& packet) {
    if (!rule_manager_) {
        return;
    }

    // TODO: 实现规则匹配
    // auto matched_rules = rule_manager_->match(packet);
    // for (const auto& rule : matched_rules) {
    //     stats_.rules_matched++;
    //     // 生成告警
    //     auto packet_info = create_packet_info(packet);
    //     auto alert = alert_generator_->generate_alert(rule, packet_info);
    //     if (alert && alert_manager_) {
    //         alert_manager_->process_alert(alert);
    //         stats_.total_alerts++;
    //     }
    // }
}

// ============================================================================
// 异常检测
// ============================================================================
// 注意：DNS 异常检测已经在 L7 解析阶段完成
// 这个方法保留用于未来扩展其他类型的异常检测

void DetectionEngine::process_anomaly_detection(Packet& packet) {
    // DNS 异常检测已经在 process_l7_parsing 中处理
    // 这里可以添加其他类型的异常检测（如流量异常等）
    (void)packet;  // 暂时未使用
}

// ============================================================================
// 辅助方法
// ============================================================================

decoders::PacketInfo DetectionEngine::create_packet_info(const Packet& packet) const {
    decoders::PacketInfo info;

    info.packet_length = packet.length();
    const auto& stack = packet.protocol_stack();

    // Ethernet
    info.has_ethernet = (stack.l2_type == ProtocolType::ETHERNET);

    // IPv4
    if (stack.l3_type == ProtocolType::IPV4 &&
        static_cast<size_t>(stack.l3_offset) + sizeof(decoders::IPv4Header) <= packet.length()) {

        const auto* ip_hdr = reinterpret_cast<const decoders::IPv4Header*>(
            packet.data() + stack.l3_offset
        );

        info.has_ipv4 = true;
        info.ipv4_src = ip_hdr->src_ip;
        info.ipv4_dst = ip_hdr->dst_ip;
        info.ipv4_ttl = ip_hdr->ttl;
        info.ipv4_protocol = ip_hdr->protocol;
    }

    // TCP
    if (stack.l4_type == ProtocolType::TCP &&
        static_cast<size_t>(stack.l4_offset) + sizeof(decoders::TcpHeader) <= packet.length()) {

        const auto* tcp_hdr = reinterpret_cast<const decoders::TcpHeader*>(
            packet.data() + stack.l4_offset
        );

        info.has_tcp = true;
        info.tcp_src_port = ntohs(tcp_hdr->src_port);
        info.tcp_dst_port = ntohs(tcp_hdr->dst_port);

        uint8_t flags = tcp_hdr->flags;
        info.tcp_flags_syn = (flags & 0x02) != 0;
        info.tcp_flags_ack = (flags & 0x10) != 0;
        info.tcp_flags_fin = (flags & 0x01) != 0;
        info.tcp_flags_rst = (flags & 0x04) != 0;
        info.tcp_flags_psh = (flags & 0x08) != 0;
        info.tcp_flags_urg = (flags & 0x20) != 0;
    }

    // UDP
    if (stack.l4_type == ProtocolType::UDP &&
        static_cast<size_t>(stack.l4_offset) + sizeof(decoders::UdpHeader) <= packet.length()) {

        const auto* udp_hdr = reinterpret_cast<const decoders::UdpHeader*>(
            packet.data() + stack.l4_offset
        );

        info.has_udp = true;
        info.udp_src_port = ntohs(udp_hdr->src_port);
        info.udp_dst_port = ntohs(udp_hdr->dst_port);
    }

    return info;
}

} // namespace core
} // namespace netguardian
