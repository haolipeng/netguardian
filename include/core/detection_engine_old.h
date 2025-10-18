#ifndef NETGUARDIAN_CORE_DETECTION_ENGINE_H
#define NETGUARDIAN_CORE_DETECTION_ENGINE_H

#include "core/packet.h"
#include "core/packet_capture.h"
#include "decoders/ethernet_decoder.h"
#include "decoders/ipv4_decoder.h"
#include "decoders/tcp_decoder.h"
#include "decoders/udp_decoder.h"
#include "decoders/http_parser.h"
#include "decoders/dns_parser.h"
#include "decoders/dns_anomaly_detector.h"
#include "flow/flow_table.h"
#include "flow/flow_manager.h"
#include "reassembly/tcp_reassembler.h"
#include "reassembly/ipv4_reassembler.h"
#include "reassembly/ipv6_reassembler.h"
#include "rules/rule_manager.h"
#include "alerts/alert_manager.h"
#include "alerts/alert_generator.h"

#include <memory>
#include <atomic>
#include <functional>

namespace netguardian {
namespace core {

// ============================================================================
// 检测引擎配置
// ============================================================================

struct DetectionEngineConfig {
    // 流管理配置
    flow::FlowTimeoutConfig flow_timeout;
    uint32_t max_flows = 100000;

    // 重组配置
    bool enable_tcp_reassembly = true;
    bool enable_ip_reassembly = true;
    uint32_t tcp_reasm_max_segments = 1024;
    uint32_t ip_reasm_timeout = 60;

    // 协议解析配置
    bool enable_http_parser = true;
    bool enable_dns_parser = true;

    // 异常检测配置
    bool enable_dns_anomaly_detection = true;
    decoders::DnsAnomalyConfig dns_anomaly_config;

    // 规则引擎配置
    std::string rules_path;
    bool auto_reload_rules = false;

    // 告警配置
    alerts::DeduplicationConfig alert_dedup_config;
    bool alert_console_output = true;
    bool alert_file_output = false;
    std::string alert_output_path;
    alerts::FileAlertOutput::FileFormat alert_output_format = alerts::FileAlertOutput::FileFormat::TEXT;

    DetectionEngineConfig() {
        // 流超时默认配置
        flow_timeout.tcp_established_timeout = 3600;
        flow_timeout.tcp_closing_timeout = 120;
        flow_timeout.tcp_closed_timeout = 5;
        flow_timeout.tcp_unknown_timeout = 300;
        flow_timeout.udp_timeout = 30;
        flow_timeout.other_timeout = 30;

        // 告警去重默认配置
        alert_dedup_config.enabled = true;
        alert_dedup_config.time_window_seconds = 60;
        alert_dedup_config.max_alerts_per_rule = 10;
    }
};

// ============================================================================
// 检测引擎统计信息
// ============================================================================

struct DetectionEngineStats {
    // 数据包统计
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> dropped_packets{0};

    // 协议统计
    std::atomic<uint64_t> ethernet_packets{0};
    std::atomic<uint64_t> ipv4_packets{0};
    std::atomic<uint64_t> ipv6_packets{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> http_packets{0};
    std::atomic<uint64_t> dns_packets{0};

    // 流统计
    std::atomic<uint64_t> total_flows{0};
    std::atomic<uint64_t> active_flows{0};

    // 重组统计
    std::atomic<uint64_t> tcp_reassembled_streams{0};
    std::atomic<uint64_t> ip_reassembled_packets{0};

    // 检测统计
    std::atomic<uint64_t> rules_matched{0};
    std::atomic<uint64_t> anomalies_detected{0};

    // 告警统计
    std::atomic<uint64_t> total_alerts{0};
    std::atomic<uint64_t> alerts_suppressed{0};

    void reset() {
        total_packets = 0;
        total_bytes = 0;
        dropped_packets = 0;
        ethernet_packets = 0;
        ipv4_packets = 0;
        ipv6_packets = 0;
        tcp_packets = 0;
        udp_packets = 0;
        http_packets = 0;
        dns_packets = 0;
        total_flows = 0;
        active_flows = 0;
        tcp_reassembled_streams = 0;
        ip_reassembled_packets = 0;
        rules_matched = 0;
        anomalies_detected = 0;
        total_alerts = 0;
        alerts_suppressed = 0;
    }
};

// ============================================================================
// 检测引擎
// ============================================================================

class DetectionEngine {
public:
    explicit DetectionEngine(const DetectionEngineConfig& config);
    ~DetectionEngine();

    // 初始化
    bool initialize();

    // 数据包处理
    void process_packet(const Packet& packet);

    // 获取统计信息
    const DetectionEngineStats& get_stats() const { return stats_; }
    flow::FlowTableStats get_flow_stats() const;

    // 规则管理
    bool load_rules(const std::string& rules_path);
    size_t get_rule_count() const;

    // 控制
    void start();
    void stop();
    void flush();  // 刷新所有缓冲区和导出流

private:
    // 配置
    DetectionEngineConfig config_;

    // 统计信息
    DetectionEngineStats stats_;

    // 运行状态
    std::atomic<bool> running_{false};
    std::atomic<bool> initialized_{false};

    // L2-L4 解码器
    std::unique_ptr<decoders::EthernetDecoder> eth_decoder_;
    std::unique_ptr<decoders::IPv4Decoder> ipv4_decoder_;
    std::unique_ptr<decoders::TcpDecoder> tcp_decoder_;
    std::unique_ptr<decoders::UdpDecoder> udp_decoder_;

    // L7 深度解析器
    std::unique_ptr<decoders::HttpParser> http_parser_;
    std::unique_ptr<decoders::DnsParser> dns_parser_;

    // 流管理
    std::unique_ptr<flow::FlowTable> flow_table_;
    std::unique_ptr<flow::FlowManager> flow_manager_;

    // 重组器
    std::unique_ptr<reassembly::TcpReassembler> tcp_reasm_;
    std::unique_ptr<reassembly::Ipv4Reassembler> ipv4_reasm_;
    std::unique_ptr<reassembly::Ipv6Reassembler> ipv6_reasm_;

    // 异常检测
    std::unique_ptr<decoders::DnsAnomalyDetector> dns_anomaly_;

    // 规则引擎
    std::unique_ptr<rules::RuleManager> rule_manager_;

    // 告警系统
    std::unique_ptr<alerts::AlertManager> alert_manager_;
    std::unique_ptr<alerts::AlertGenerator> alert_generator_;

    // 内部处理方法
    bool parse_protocols(Packet& packet);
    void process_flow(Packet& packet);
    void process_reassembly(Packet& packet);
    void process_l7_parsing(Packet& packet);
    void process_detection(Packet& packet);
    void process_anomaly_detection(Packet& packet);

    // 辅助方法
    flow::FlowKey extract_flow_key(const Packet& packet) const;
    decoders::PacketInfo create_packet_info(const Packet& packet) const;
};

} // namespace core
} // namespace netguardian

#endif // NETGUARDIAN_CORE_DETECTION_ENGINE_H
