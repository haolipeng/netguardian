#ifndef NETGUARDIAN_ALERTS_ALERT_H
#define NETGUARDIAN_ALERTS_ALERT_H

#include <string>
#include <chrono>
#include <cstdint>
#include <vector>
#include <memory>
#include <sstream>
#include <iomanip>

namespace netguardian {
namespace alerts {

// 告警优先级
enum class AlertPriority {
    LOW = 1,      // 低优先级（信息性）
    MEDIUM = 2,   // 中等优先级（可疑活动）
    HIGH = 3,     // 高优先级（确认威胁）
    CRITICAL = 4  // 严重（紧急响应）
};

// 告警分类
enum class AlertCategory {
    UNKNOWN,              // 未知
    PROTOCOL_ANOMALY,     // 协议异常
    MALWARE,              // 恶意软件
    EXPLOIT,              // 漏洞利用
    POLICY_VIOLATION,     // 策略违规
    DOS_ATTACK,           // 拒绝服务攻击
    SCAN,                 // 扫描活动
    RECONNAISSANCE,       // 侦察
    INTRUSION,            // 入侵
    DATA_EXFILTRATION,    // 数据泄露
    COMMAND_AND_CONTROL,  // C&C 通信
    WEB_ATTACK,           // Web 攻击
    NETWORK_ATTACK,       // 网络攻击
    SUSPICIOUS_TRAFFIC    // 可疑流量
};

// 告警动作（来自规则）
enum class AlertAction {
    ALERT,   // 生成告警
    LOG,     // 仅记录日志
    PASS,    // 通过（不告警）
    DROP,    // 丢弃数据包（IPS 模式）
    REJECT,  // 拒绝并发送 RST/ICMP（IPS 模式）
    SDROP    // 静默丢弃（IPS 模式）
};

// 协议类型字符串转换
inline std::string protocol_to_string(uint8_t protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "Unknown(" + std::to_string(protocol) + ")";
    }
}

// 优先级字符串转换
inline std::string priority_to_string(AlertPriority priority) {
    switch (priority) {
        case AlertPriority::LOW: return "LOW";
        case AlertPriority::MEDIUM: return "MEDIUM";
        case AlertPriority::HIGH: return "HIGH";
        case AlertPriority::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

// 分类字符串转换
inline std::string category_to_string(AlertCategory category) {
    switch (category) {
        case AlertCategory::PROTOCOL_ANOMALY: return "Protocol Anomaly";
        case AlertCategory::MALWARE: return "Malware";
        case AlertCategory::EXPLOIT: return "Exploit";
        case AlertCategory::POLICY_VIOLATION: return "Policy Violation";
        case AlertCategory::DOS_ATTACK: return "DoS Attack";
        case AlertCategory::SCAN: return "Scan";
        case AlertCategory::RECONNAISSANCE: return "Reconnaissance";
        case AlertCategory::INTRUSION: return "Intrusion";
        case AlertCategory::DATA_EXFILTRATION: return "Data Exfiltration";
        case AlertCategory::COMMAND_AND_CONTROL: return "C&C Communication";
        case AlertCategory::WEB_ATTACK: return "Web Attack";
        case AlertCategory::NETWORK_ATTACK: return "Network Attack";
        case AlertCategory::SUSPICIOUS_TRAFFIC: return "Suspicious Traffic";
        default: return "Unknown";
    }
}

// 动作字符串转换
inline std::string action_to_string(AlertAction action) {
    switch (action) {
        case AlertAction::ALERT: return "ALERT";
        case AlertAction::LOG: return "LOG";
        case AlertAction::PASS: return "PASS";
        case AlertAction::DROP: return "DROP";
        case AlertAction::REJECT: return "REJECT";
        case AlertAction::SDROP: return "SDROP";
        default: return "UNKNOWN";
    }
}

// 告警结构
struct Alert {
    // 基本信息
    uint64_t alert_id;                              // 告警唯一 ID
    std::chrono::system_clock::time_point timestamp; // 告警时间戳

    // 规则信息
    uint32_t signature_id;                          // 规则签名 ID (sid)
    uint32_t revision;                              // 规则版本 (rev)
    std::string message;                            // 告警消息
    AlertAction action;                             // 告警动作
    AlertPriority priority;                         // 优先级
    AlertCategory category;                         // 分类

    // 网络五元组信息
    std::string src_ip;                             // 源 IP
    std::string dst_ip;                             // 目标 IP
    uint16_t src_port;                              // 源端口
    uint16_t dst_port;                              // 目标端口
    uint8_t protocol;                               // 协议

    // 数据包信息
    uint32_t packet_length;                         // 数据包长度
    std::vector<uint8_t> packet_data;               // 数据包原始数据（可选）

    // 匹配信息
    std::vector<std::string> matched_patterns;      // 匹配的模式
    std::string additional_info;                    // 附加信息

    // 构造函数
    Alert()
        : alert_id(0)
        , timestamp(std::chrono::system_clock::now())
        , signature_id(0)
        , revision(0)
        , action(AlertAction::ALERT)
        , priority(AlertPriority::MEDIUM)
        , category(AlertCategory::UNKNOWN)
        , src_port(0)
        , dst_port(0)
        , protocol(0)
        , packet_length(0)
    {}

    // 生成人类可读的告警字符串
    std::string to_string() const {
        std::ostringstream oss;

        // 时间戳格式化
        auto time_t = std::chrono::system_clock::to_time_t(timestamp);
        auto tm = *std::localtime(&time_t);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamp.time_since_epoch()
        ) % 1000;

        oss << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
            << "." << std::setfill('0') << std::setw(3) << ms.count() << "] ";

        // 优先级和动作
        oss << "[" << priority_to_string(priority) << "] "
            << "[" << action_to_string(action) << "] ";

        // 规则信息
        oss << message << " [SID:" << signature_id << ":" << revision << "] ";

        // 五元组
        oss << src_ip << ":" << src_port << " -> "
            << dst_ip << ":" << dst_port << " "
            << protocol_to_string(protocol);

        // 附加信息
        if (!additional_info.empty()) {
            oss << " | " << additional_info;
        }

        return oss.str();
    }

    // 生成 JSON 格式的告警
    std::string to_json() const {
        std::ostringstream oss;

        // 时间戳格式化为 ISO 8601
        auto time_t = std::chrono::system_clock::to_time_t(timestamp);
        auto tm = *std::gmtime(&time_t);

        oss << "{\n";
        oss << "  \"alert_id\": " << alert_id << ",\n";
        oss << "  \"timestamp\": \"" << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << "Z\",\n";
        oss << "  \"signature_id\": " << signature_id << ",\n";
        oss << "  \"revision\": " << revision << ",\n";
        oss << "  \"message\": \"" << escape_json(message) << "\",\n";
        oss << "  \"action\": \"" << action_to_string(action) << "\",\n";
        oss << "  \"priority\": \"" << priority_to_string(priority) << "\",\n";
        oss << "  \"category\": \"" << category_to_string(category) << "\",\n";
        oss << "  \"src_ip\": \"" << src_ip << "\",\n";
        oss << "  \"dst_ip\": \"" << dst_ip << "\",\n";
        oss << "  \"src_port\": " << src_port << ",\n";
        oss << "  \"dst_port\": " << dst_port << ",\n";
        oss << "  \"protocol\": \"" << protocol_to_string(protocol) << "\",\n";
        oss << "  \"packet_length\": " << packet_length;

        if (!additional_info.empty()) {
            oss << ",\n  \"additional_info\": \"" << escape_json(additional_info) << "\"";
        }

        oss << "\n}";
        return oss.str();
    }

    // 生成 CSV 格式的告警（单行）
    std::string to_csv() const {
        std::ostringstream oss;

        // 时间戳
        auto time_t = std::chrono::system_clock::to_time_t(timestamp);
        auto tm = *std::localtime(&time_t);
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << ",";

        // 基本信息
        oss << alert_id << ","
            << signature_id << ","
            << revision << ","
            << "\"" << escape_csv(message) << "\","
            << priority_to_string(priority) << ","
            << action_to_string(action) << ","
            << category_to_string(category) << ",";

        // 五元组
        oss << src_ip << ","
            << src_port << ","
            << dst_ip << ","
            << dst_port << ","
            << protocol_to_string(protocol) << ","
            << packet_length;

        return oss.str();
    }

    // CSV 表头
    static std::string csv_header() {
        return "timestamp,alert_id,signature_id,revision,message,priority,action,category,"
               "src_ip,src_port,dst_ip,dst_port,protocol,packet_length";
    }

private:
    // JSON 字符串转义
    static std::string escape_json(const std::string& str) {
        std::ostringstream oss;
        for (char c : str) {
            switch (c) {
                case '"': oss << "\\\""; break;
                case '\\': oss << "\\\\"; break;
                case '\b': oss << "\\b"; break;
                case '\f': oss << "\\f"; break;
                case '\n': oss << "\\n"; break;
                case '\r': oss << "\\r"; break;
                case '\t': oss << "\\t"; break;
                default: oss << c; break;
            }
        }
        return oss.str();
    }

    // CSV 字符串转义
    static std::string escape_csv(const std::string& str) {
        std::string result = str;
        // 如果包含逗号、引号或换行符，需要用引号包围并转义引号
        if (result.find(',') != std::string::npos ||
            result.find('"') != std::string::npos ||
            result.find('\n') != std::string::npos) {
            size_t pos = 0;
            while ((pos = result.find('"', pos)) != std::string::npos) {
                result.replace(pos, 1, "\"\"");
                pos += 2;
            }
        }
        return result;
    }
};

} // namespace alerts
} // namespace netguardian

#endif // NETGUARDIAN_ALERTS_ALERT_H
