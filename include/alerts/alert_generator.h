#ifndef NETGUARDIAN_ALERTS_ALERT_GENERATOR_H
#define NETGUARDIAN_ALERTS_ALERT_GENERATOR_H

#include "alerts/alert.h"
#include "rules/rule.h"
#include "decoders/packet_info.h"
#include <atomic>
#include <memory>
#include <arpa/inet.h>

namespace netguardian {
namespace alerts {

// 告警生成器
class AlertGenerator {
public:
    AlertGenerator()
        : next_alert_id_(1)
    {}

    // 从规则和数据包信息生成告警
    std::shared_ptr<Alert> generate_alert(
        const rules::Rule& rule,
        const decoders::PacketInfo& packet_info,
        const std::vector<std::string>& matched_patterns = {}
    ) {
        auto alert = std::make_shared<Alert>();

        // 分配告警 ID
        alert->alert_id = next_alert_id_++;
        alert->timestamp = std::chrono::system_clock::now();

        // 规则信息
        alert->signature_id = rule.sid();
        alert->revision = rule.rev();
        alert->message = rule.message();
        alert->action = parse_action(action_to_string(rule.header().action));
        alert->priority = parse_priority(rule.priority());
        alert->category = parse_category(rule.classtype());

        // 提取网络信息
        extract_network_info(packet_info, *alert);

        // 数据包信息
        alert->packet_length = packet_info.packet_length;

        // 匹配信息
        alert->matched_patterns = matched_patterns;

        // 附加信息
        build_additional_info(rule, packet_info, *alert);

        return alert;
    }

    // 重置告警 ID 计数器（用于测试）
    void reset_alert_id() {
        next_alert_id_ = 1;
    }

    // 获取生成的告警总数
    uint64_t get_total_alerts() const {
        return next_alert_id_ - 1;
    }

private:
    std::atomic<uint64_t> next_alert_id_;

    // 解析告警动作
    AlertAction parse_action(const std::string& action) {
        if (action == "alert") return AlertAction::ALERT;
        if (action == "log") return AlertAction::LOG;
        if (action == "pass") return AlertAction::PASS;
        if (action == "drop") return AlertAction::DROP;
        if (action == "reject") return AlertAction::REJECT;
        if (action == "sdrop") return AlertAction::SDROP;
        return AlertAction::ALERT;
    }

    // 解析优先级
    AlertPriority parse_priority(int priority) {
        switch (priority) {
            case 1: return AlertPriority::CRITICAL;
            case 2: return AlertPriority::HIGH;
            case 3: return AlertPriority::MEDIUM;
            case 4: return AlertPriority::LOW;
            default: return AlertPriority::MEDIUM;
        }
    }

    // 解析分类
    AlertCategory parse_category(const std::string& classtype) {
        if (classtype.find("exploit") != std::string::npos)
            return AlertCategory::EXPLOIT;
        if (classtype.find("malware") != std::string::npos)
            return AlertCategory::MALWARE;
        if (classtype.find("web") != std::string::npos)
            return AlertCategory::WEB_ATTACK;
        if (classtype.find("dos") != std::string::npos || classtype.find("ddos") != std::string::npos)
            return AlertCategory::DOS_ATTACK;
        if (classtype.find("scan") != std::string::npos)
            return AlertCategory::SCAN;
        if (classtype.find("recon") != std::string::npos)
            return AlertCategory::RECONNAISSANCE;
        if (classtype.find("policy") != std::string::npos)
            return AlertCategory::POLICY_VIOLATION;
        if (classtype.find("trojan") != std::string::npos || classtype.find("backdoor") != std::string::npos)
            return AlertCategory::COMMAND_AND_CONTROL;
        if (classtype.find("data") != std::string::npos && classtype.find("leak") != std::string::npos)
            return AlertCategory::DATA_EXFILTRATION;
        if (classtype.find("protocol") != std::string::npos || classtype.find("anomaly") != std::string::npos)
            return AlertCategory::PROTOCOL_ANOMALY;
        if (classtype.find("suspicious") != std::string::npos)
            return AlertCategory::SUSPICIOUS_TRAFFIC;

        return AlertCategory::UNKNOWN;
    }

    // 提取网络信息
    void extract_network_info(const decoders::PacketInfo& packet_info, Alert& alert) {
        // 提取 IP 地址
        if (packet_info.has_ipv4) {
            alert.src_ip = ipv4_to_string(packet_info.ipv4_src);
            alert.dst_ip = ipv4_to_string(packet_info.ipv4_dst);
        } else if (packet_info.has_ipv6) {
            alert.src_ip = "[IPv6]";  // 简化处理，实际应该格式化 IPv6
            alert.dst_ip = "[IPv6]";
        }

        // 提取端口信息
        if (packet_info.has_tcp) {
            alert.src_port = packet_info.tcp_src_port;
            alert.dst_port = packet_info.tcp_dst_port;
            alert.protocol = 6;  // TCP
        } else if (packet_info.has_udp) {
            alert.src_port = packet_info.udp_src_port;
            alert.dst_port = packet_info.udp_dst_port;
            alert.protocol = 17;  // UDP
        } else if (packet_info.has_icmp) {
            alert.src_port = 0;
            alert.dst_port = 0;
            alert.protocol = 1;  // ICMP
        }
    }

    // 构建附加信息
    void build_additional_info(
        const rules::Rule& rule,
        const decoders::PacketInfo& packet_info,
        Alert& alert
    ) {
        std::ostringstream oss;

        // 添加规则引用信息
        auto ref_opt = rule.get_option(rules::RuleOptionType::REFERENCE);
        if (ref_opt && ref_opt->has_value) {
            oss << "Reference: " << ref_opt->value << "; ";
        }

        // 添加 TCP 标志信息
        if (packet_info.has_tcp) {
            oss << "TCP Flags: ";
            if (packet_info.tcp_flags_syn) oss << "S";
            if (packet_info.tcp_flags_ack) oss << "A";
            if (packet_info.tcp_flags_fin) oss << "F";
            if (packet_info.tcp_flags_rst) oss << "R";
            if (packet_info.tcp_flags_psh) oss << "P";
            if (packet_info.tcp_flags_urg) oss << "U";
            oss << "; ";
        }

        // 添加 TTL 信息
        if (packet_info.has_ipv4) {
            oss << "TTL: " << static_cast<int>(packet_info.ipv4_ttl) << "; ";
        }

        alert.additional_info = oss.str();
    }

    // IPv4 地址转字符串
    std::string ipv4_to_string(uint32_t ip) {
        struct in_addr addr;
        addr.s_addr = ip;
        return inet_ntoa(addr);
    }
};

} // namespace alerts
} // namespace netguardian

#endif // NETGUARDIAN_ALERTS_ALERT_GENERATOR_H
