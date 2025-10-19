#ifndef NETGUARDIAN_CORE_STATISTICS_COLLECTOR_H
#define NETGUARDIAN_CORE_STATISTICS_COLLECTOR_H

#include "core/packet.h"
#include "core/protocol_types.h"
#include "flow/flow.h"
#include <atomic>
#include <mutex>
#include <cstdint>

namespace netguardian {
namespace core {

/**
 * PipelineStatsSnapshot - 管道统计信息快照（普通类型）
 *
 * 用于读取统计信息的快照
 */
struct PipelineStatsSnapshot {
    // 数据包统计
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t dropped_packets;

    // 协议统计
    uint64_t ethernet_packets;
    uint64_t ipv4_packets;
    uint64_t ipv6_packets;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t http_packets;
    uint64_t dns_packets;

    // 流统计
    uint64_t total_flows;
    uint64_t active_flows;

    // 重组统计
    uint64_t tcp_reassembled_streams;
    uint64_t ip_reassembled_packets;

    // 检测统计
    uint64_t rules_matched;
    uint64_t anomalies_detected;

    // 告警统计
    uint64_t total_alerts;
    uint64_t alerts_suppressed;

    PipelineStatsSnapshot()
        : total_packets(0), total_bytes(0), dropped_packets(0)
        , ethernet_packets(0), ipv4_packets(0), ipv6_packets(0)
        , tcp_packets(0), udp_packets(0), http_packets(0), dns_packets(0)
        , total_flows(0), active_flows(0)
        , tcp_reassembled_streams(0), ip_reassembled_packets(0)
        , rules_matched(0), anomalies_detected(0)
        , total_alerts(0), alerts_suppressed(0)
    {}
};

/**
 * PipelineStats - 管道统计信息结构（原子类型）
 *
 * 注意：使用 atomic 类型以支持多线程环境
 * 不可拷贝，但可以创建快照
 */
struct PipelineStats {
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

    // 创建快照（用于读取统计信息）
    PipelineStatsSnapshot snapshot() const {
        PipelineStatsSnapshot copy;
        copy.total_packets = total_packets.load();
        copy.total_bytes = total_bytes.load();
        copy.dropped_packets = dropped_packets.load();
        copy.ethernet_packets = ethernet_packets.load();
        copy.ipv4_packets = ipv4_packets.load();
        copy.ipv6_packets = ipv6_packets.load();
        copy.tcp_packets = tcp_packets.load();
        copy.udp_packets = udp_packets.load();
        copy.http_packets = http_packets.load();
        copy.dns_packets = dns_packets.load();
        copy.total_flows = total_flows.load();
        copy.active_flows = active_flows.load();
        copy.tcp_reassembled_streams = tcp_reassembled_streams.load();
        copy.ip_reassembled_packets = ip_reassembled_packets.load();
        copy.rules_matched = rules_matched.load();
        copy.anomalies_detected = anomalies_detected.load();
        copy.total_alerts = total_alerts.load();
        copy.alerts_suppressed = alerts_suppressed.load();
        return copy;
    }
};

/**
 * StatisticsCollector - 统计收集器
 *
 * 负责收集各种统计信息，服务于 PacketPipeline。
 *
 * 设计原则：
 * - 线程安全：使用 atomic 类型
 * - 高性能：避免锁，使用 atomic 操作
 * - 单一职责：只做统计收集
 */
class StatisticsCollector {
public:
    StatisticsCollector() = default;

    // 禁止拷贝（避免统计数据混乱）
    StatisticsCollector(const StatisticsCollector&) = delete;
    StatisticsCollector& operator=(const StatisticsCollector&) = delete;

    // ========================================================================
    // 数据包统计
    // ========================================================================

    void record_packet(const Packet& packet) {
        stats_.total_packets++;
        stats_.total_bytes += packet.length();
    }

    void record_dropped_packet() {
        stats_.dropped_packets++;
    }

    // ========================================================================
    // 协议统计
    // ========================================================================

    void record_protocols(const ProtocolStack& stack) {
        // L2
        if (stack.l2_type() == ProtocolType::ETHERNET) {
            stats_.ethernet_packets++;
        }

        // L3
        if (stack.l3_type() == ProtocolType::IPV4) {
            stats_.ipv4_packets++;
        } else if (stack.l3_type() == ProtocolType::IPV6) {
            stats_.ipv6_packets++;
        }

        // L4
        if (stack.l4_type() == ProtocolType::TCP) {
            stats_.tcp_packets++;
        } else if (stack.l4_type() == ProtocolType::UDP) {
            stats_.udp_packets++;
        }
    }

    void record_http() {
        stats_.http_packets++;
    }

    void record_dns() {
        stats_.dns_packets++;
    }

    // ========================================================================
    // 流统计
    // ========================================================================

    void record_new_flow() {
        stats_.total_flows++;
        stats_.active_flows++;
    }

    void record_flow_timeout() {
        if (stats_.active_flows > 0) {
            stats_.active_flows--;
        }
    }

    void set_active_flows(uint64_t count) {
        stats_.active_flows = count;
    }

    // ========================================================================
    // 重组统计
    // ========================================================================

    void record_tcp_segment() {
        // TCP 段已添加到重组器（可选统计）
    }

    void record_tcp_reassembly() {
        stats_.tcp_reassembled_streams++;
    }

    void record_ip_reassembly() {
        stats_.ip_reassembled_packets++;
    }

    // ========================================================================
    // 检测统计
    // ========================================================================

    void record_rule_match() {
        stats_.rules_matched++;
    }

    void record_anomaly() {
        stats_.anomalies_detected++;
    }

    void record_anomalies(size_t count) {
        stats_.anomalies_detected += count;
    }

    // ========================================================================
    // 告警统计
    // ========================================================================

    void record_alert() {
        stats_.total_alerts++;
    }

    void record_suppressed_alert() {
        stats_.alerts_suppressed++;
    }

    // ========================================================================
    // 访问接口
    // ========================================================================

    /**
     * 获取统计信息（返回引用，小心多线程访问）
     */
    const PipelineStats& stats() const {
        return stats_;
    }

    /**
     * 获取统计信息快照（线程安全）
     */
    PipelineStatsSnapshot snapshot() const {
        return stats_.snapshot();
    }

    /**
     * 重置统计信息
     */
    void reset() {
        stats_.reset();
    }

private:
    PipelineStats stats_;
};

} // namespace core
} // namespace netguardian

#endif // NETGUARDIAN_CORE_STATISTICS_COLLECTOR_H
