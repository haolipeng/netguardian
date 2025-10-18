#ifndef NETGUARDIAN_DECODERS_DNS_ANOMALY_DETECTOR_H
#define NETGUARDIAN_DECODERS_DNS_ANOMALY_DETECTOR_H

#include "decoders/dns_parser.h"
#include <vector>
#include <string>
#include <unordered_set>
#include <memory>

namespace netguardian {
namespace decoders {

// ============================================================================
// DNS 异常类型
// ============================================================================

enum class DnsAnomalyType {
    // 域名异常
    LONG_DOMAIN,            // 超长域名（> 255 字节）
    LONG_LABEL,             // 超长标签（> 63 字节）
    HIGH_ENTROPY_DOMAIN,    // 高熵值域名（可能是 DGA）
    DEEP_SUBDOMAIN,         // 子域名层级过深（> 10 层）
    NUMERIC_HEAVY,          // 数字占比过高

    // DNS 隧道特征
    TUNNEL_SUSPECTED,       // 疑似 DNS 隧道
    LARGE_TXT_RECORD,       // 大 TXT 记录
    EXCESSIVE_QUERIES,      // 查询频率过高
    ENCODED_DATA,           // 包含编码数据

    // 协议异常
    PROTOCOL_ERROR,         // 协议错误（FORMERR）
    UNUSUAL_QUERY_TYPE,     // 罕见查询类型
    TRUNCATED_RESPONSE,     // 响应被截断
    INVALID_RESPONSE_CODE,  // 异常响应代码

    // 可疑行为
    RAPID_NXDOMAIN,         // 快速连续 NXDOMAIN
    BLACKLISTED_IP,         // IP 在黑名单中
    SUSPICIOUS_TLD,         // 可疑顶级域名
    ZERO_TTL               // TTL 为 0
};

// ============================================================================
// DNS 异常
// ============================================================================

struct DnsAnomaly {
    DnsAnomalyType type;
    std::string description;
    double severity;        // 严重程度 0.0 - 1.0
    std::string evidence;   // 证据信息

    DnsAnomaly(DnsAnomalyType t, const std::string& desc, double sev, const std::string& ev = "")
        : type(t), description(desc), severity(sev), evidence(ev)
    {}

    std::string to_string() const;
    static std::string type_to_string(DnsAnomalyType type);
};

// ============================================================================
// DNS 异常检测器配置
// ============================================================================

struct DnsAnomalyConfig {
    // 域名限制
    size_t max_domain_length;       // 默认 255
    size_t max_label_length;        // 默认 63
    int max_subdomain_levels;       // 默认 10

    // 熵值阈值
    double entropy_threshold;       // 默认 3.5（高于此值可能是 DGA）
    double numeric_ratio_threshold; // 默认 0.6（数字占比）

    // DNS 隧道检测
    size_t max_txt_length;          // 默认 512 字节
    size_t tunnel_query_threshold;  // 默认 100 查询/分钟

    // 可疑 TLD
    std::unordered_set<std::string> suspicious_tlds;

    // 黑名单 IP（示例）
    std::unordered_set<std::string> blacklisted_ips;

    DnsAnomalyConfig()
        : max_domain_length(255)
        , max_label_length(63)
        , max_subdomain_levels(10)
        , entropy_threshold(3.5)
        , numeric_ratio_threshold(0.6)
        , max_txt_length(512)
        , tunnel_query_threshold(100)
    {
        // 添加一些常见的可疑 TLD
        suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq"};
    }
};

// ============================================================================
// DNS 异常检测器
// ============================================================================

class DnsAnomalyDetector {
public:
    explicit DnsAnomalyDetector(const DnsAnomalyConfig& config = DnsAnomalyConfig())
        : config_(config)
    {}

    // 检测单个 DNS 消息的异常
    std::vector<DnsAnomaly> detect(const DnsMessage& message);

    // 获取和设置配置
    const DnsAnomalyConfig& config() const { return config_; }
    void set_config(const DnsAnomalyConfig& config) { config_ = config; }

    // 添加黑名单 IP
    void add_blacklisted_ip(const std::string& ip) {
        config_.blacklisted_ips.insert(ip);
    }

    // 添加可疑 TLD
    void add_suspicious_tld(const std::string& tld) {
        config_.suspicious_tlds.insert(tld);
    }

private:
    DnsAnomalyConfig config_;

    // 域名异常检测
    bool is_long_domain(const std::string& domain) const;
    bool has_long_label(const std::string& domain) const;
    bool is_high_entropy(const std::string& domain) const;
    bool is_deep_subdomain(const std::string& domain) const;
    bool is_numeric_heavy(const std::string& domain) const;

    // DNS 隧道检测
    bool is_tunnel_suspected(const DnsMessage& message) const;
    bool has_large_txt_record(const DnsMessage& message) const;
    bool has_encoded_data(const std::string& domain) const;

    // 协议异常检测
    bool has_protocol_error(const DnsMessage& message) const;
    bool has_unusual_query_type(const DnsMessage& message) const;

    // 可疑行为检测
    bool has_blacklisted_ip(const DnsMessage& message) const;
    bool has_suspicious_tld(const std::string& domain) const;
    bool has_zero_ttl(const DnsMessage& message) const;

    // 辅助方法
    double calculate_entropy(const std::string& str) const;
    int count_subdomain_levels(const std::string& domain) const;
    double calculate_numeric_ratio(const std::string& str) const;
    std::string extract_tld(const std::string& domain) const;
};

} // namespace decoders
} // namespace netguardian

#endif // NETGUARDIAN_DECODERS_DNS_ANOMALY_DETECTOR_H
