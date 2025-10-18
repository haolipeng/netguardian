#include "decoders/dns_anomaly_detector.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cmath>
#include <unordered_map>

namespace netguardian {
namespace decoders {

// ============================================================================
// DnsAnomaly 实现
// ============================================================================

std::string DnsAnomaly::to_string() const {
    std::ostringstream oss;
    oss << "[" << type_to_string(type) << "] ";
    oss << description;
    oss << " (severity: " << std::fixed << std::setprecision(2) << severity << ")";
    if (!evidence.empty()) {
        oss << " - " << evidence;
    }
    return oss.str();
}

std::string DnsAnomaly::type_to_string(DnsAnomalyType type) {
    switch (type) {
        case DnsAnomalyType::LONG_DOMAIN: return "LONG_DOMAIN";
        case DnsAnomalyType::LONG_LABEL: return "LONG_LABEL";
        case DnsAnomalyType::HIGH_ENTROPY_DOMAIN: return "HIGH_ENTROPY_DOMAIN";
        case DnsAnomalyType::DEEP_SUBDOMAIN: return "DEEP_SUBDOMAIN";
        case DnsAnomalyType::NUMERIC_HEAVY: return "NUMERIC_HEAVY";
        case DnsAnomalyType::TUNNEL_SUSPECTED: return "TUNNEL_SUSPECTED";
        case DnsAnomalyType::LARGE_TXT_RECORD: return "LARGE_TXT_RECORD";
        case DnsAnomalyType::EXCESSIVE_QUERIES: return "EXCESSIVE_QUERIES";
        case DnsAnomalyType::ENCODED_DATA: return "ENCODED_DATA";
        case DnsAnomalyType::PROTOCOL_ERROR: return "PROTOCOL_ERROR";
        case DnsAnomalyType::UNUSUAL_QUERY_TYPE: return "UNUSUAL_QUERY_TYPE";
        case DnsAnomalyType::TRUNCATED_RESPONSE: return "TRUNCATED_RESPONSE";
        case DnsAnomalyType::INVALID_RESPONSE_CODE: return "INVALID_RESPONSE_CODE";
        case DnsAnomalyType::RAPID_NXDOMAIN: return "RAPID_NXDOMAIN";
        case DnsAnomalyType::BLACKLISTED_IP: return "BLACKLISTED_IP";
        case DnsAnomalyType::SUSPICIOUS_TLD: return "SUSPICIOUS_TLD";
        case DnsAnomalyType::ZERO_TTL: return "ZERO_TTL";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// DnsAnomalyDetector 公共方法
// ============================================================================

std::vector<DnsAnomaly> DnsAnomalyDetector::detect(const DnsMessage& message) {
    std::vector<DnsAnomaly> anomalies;

    // 检查所有查询的域名
    for (const auto& question : message.questions) {
        const std::string& domain = question.qname;

        // 域名异常检测
        if (is_long_domain(domain)) {
            anomalies.emplace_back(
                DnsAnomalyType::LONG_DOMAIN,
                "Domain name exceeds maximum length",
                0.7,
                "Domain: " + domain + " (length: " + std::to_string(domain.length()) + ")"
            );
        }

        if (has_long_label(domain)) {
            anomalies.emplace_back(
                DnsAnomalyType::LONG_LABEL,
                "Domain contains label exceeding 63 bytes",
                0.6,
                "Domain: " + domain
            );
        }

        if (is_high_entropy(domain)) {
            double entropy = calculate_entropy(domain);
            anomalies.emplace_back(
                DnsAnomalyType::HIGH_ENTROPY_DOMAIN,
                "High entropy domain (possible DGA)",
                0.8,
                "Domain: " + domain + " (entropy: " + std::to_string(entropy) + ")"
            );
        }

        if (is_deep_subdomain(domain)) {
            int levels = count_subdomain_levels(domain);
            anomalies.emplace_back(
                DnsAnomalyType::DEEP_SUBDOMAIN,
                "Domain has excessive subdomain levels",
                0.5,
                "Domain: " + domain + " (levels: " + std::to_string(levels) + ")"
            );
        }

        if (is_numeric_heavy(domain)) {
            double ratio = calculate_numeric_ratio(domain);
            anomalies.emplace_back(
                DnsAnomalyType::NUMERIC_HEAVY,
                "Domain has high numeric character ratio",
                0.5,
                "Domain: " + domain + " (ratio: " + std::to_string(ratio) + ")"
            );
        }

        if (has_suspicious_tld(domain)) {
            anomalies.emplace_back(
                DnsAnomalyType::SUSPICIOUS_TLD,
                "Domain uses suspicious TLD",
                0.6,
                "Domain: " + domain
            );
        }

        if (has_encoded_data(domain)) {
            anomalies.emplace_back(
                DnsAnomalyType::ENCODED_DATA,
                "Domain contains possible encoded data",
                0.7,
                "Domain: " + domain
            );
        }
    }

    // DNS 隧道检测
    if (is_tunnel_suspected(message)) {
        anomalies.emplace_back(
            DnsAnomalyType::TUNNEL_SUSPECTED,
            "DNS tunneling activity suspected",
            0.9,
            "Multiple indicators present"
        );
    }

    if (has_large_txt_record(message)) {
        anomalies.emplace_back(
            DnsAnomalyType::LARGE_TXT_RECORD,
            "TXT record exceeds normal size",
            0.7,
            "Possible data exfiltration"
        );
    }

    // 协议异常检测
    if (has_protocol_error(message)) {
        anomalies.emplace_back(
            DnsAnomalyType::PROTOCOL_ERROR,
            "DNS protocol error detected",
            0.5,
            "RCODE: " + DnsParser::rcode_to_string(message.flags.rcode)
        );
    }

    if (has_unusual_query_type(message)) {
        anomalies.emplace_back(
            DnsAnomalyType::UNUSUAL_QUERY_TYPE,
            "Unusual DNS query type detected",
            0.4,
            "Rare query type used"
        );
    }

    if (message.flags.tc && message.is_response()) {
        anomalies.emplace_back(
            DnsAnomalyType::TRUNCATED_RESPONSE,
            "DNS response is truncated",
            0.3,
            "TC flag set"
        );
    }

    // 可疑行为检测
    if (has_blacklisted_ip(message)) {
        anomalies.emplace_back(
            DnsAnomalyType::BLACKLISTED_IP,
            "Response contains blacklisted IP",
            1.0,
            "Known malicious IP address"
        );
    }

    if (has_zero_ttl(message)) {
        anomalies.emplace_back(
            DnsAnomalyType::ZERO_TTL,
            "Resource record has zero TTL",
            0.4,
            "Unusual caching behavior"
        );
    }

    return anomalies;
}

// ============================================================================
// 域名异常检测
// ============================================================================

bool DnsAnomalyDetector::is_long_domain(const std::string& domain) const {
    return domain.length() > config_.max_domain_length;
}

bool DnsAnomalyDetector::has_long_label(const std::string& domain) const {
    size_t start = 0;
    for (size_t i = 0; i <= domain.length(); i++) {
        if (i == domain.length() || domain[i] == '.') {
            size_t label_len = i - start;
            if (label_len > config_.max_label_length) {
                return true;
            }
            start = i + 1;
        }
    }
    return false;
}

bool DnsAnomalyDetector::is_high_entropy(const std::string& domain) const {
    // 只计算主域名部分的熵（去除 TLD）
    size_t last_dot = domain.rfind('.');
    std::string main_part = (last_dot != std::string::npos) ?
                           domain.substr(0, last_dot) : domain;

    // 移除所有点
    main_part.erase(std::remove(main_part.begin(), main_part.end(), '.'), main_part.end());

    if (main_part.length() < 6) {
        return false;  // 太短不计算
    }

    double entropy = calculate_entropy(main_part);
    return entropy > config_.entropy_threshold;
}

bool DnsAnomalyDetector::is_deep_subdomain(const std::string& domain) const {
    int levels = count_subdomain_levels(domain);
    return levels > config_.max_subdomain_levels;
}

bool DnsAnomalyDetector::is_numeric_heavy(const std::string& domain) const {
    double ratio = calculate_numeric_ratio(domain);
    return ratio > config_.numeric_ratio_threshold;
}

// ============================================================================
// DNS 隧道检测
// ============================================================================

bool DnsAnomalyDetector::is_tunnel_suspected(const DnsMessage& message) const {
    int indicators = 0;

    // 检查多个指标
    for (const auto& question : message.questions) {
        // 长域名
        if (question.qname.length() > 100) indicators++;

        // 高熵值
        if (is_high_entropy(question.qname)) indicators++;

        // 包含编码数据
        if (has_encoded_data(question.qname)) indicators++;

        // NULL 类型查询（常用于隧道）
        if (question.qtype == DnsRecordType::NULL_RECORD) indicators++;

        // TXT 查询（可能用于数据传输）
        if (question.qtype == DnsRecordType::TXT && question.qname.length() > 50) {
            indicators++;
        }
    }

    // 大 TXT 记录
    if (has_large_txt_record(message)) indicators++;

    // 如果有 3 个或更多指标，认为可疑
    return indicators >= 3;
}

bool DnsAnomalyDetector::has_large_txt_record(const DnsMessage& message) const {
    for (const auto& answer : message.answers) {
        if (answer.type == DnsRecordType::TXT) {
            if (answer.rdlength > config_.max_txt_length) {
                return true;
            }
        }
    }
    return false;
}

bool DnsAnomalyDetector::has_encoded_data(const std::string& domain) const {
    // 检测 Base64/Hex 编码特征
    // Base64: 连续的字母数字字符，可能包含 - 或 _
    // Hex: 只包含 0-9, a-f

    // 提取主域名部分（不含 TLD）
    size_t last_dot = domain.rfind('.');
    std::string main_part = (last_dot != std::string::npos) ?
                           domain.substr(0, last_dot) : domain;

    if (main_part.length() < 20) {
        return false;  // 太短
    }

    // 检查是否看起来像 Base64
    int base64_chars = 0;
    for (char c : main_part) {
        if (std::isalnum(c) || c == '-' || c == '_') {
            base64_chars++;
        }
    }

    double base64_ratio = static_cast<double>(base64_chars) / main_part.length();
    if (base64_ratio > 0.9 && main_part.length() > 32) {
        return true;
    }

    // 检查是否看起来像 Hex
    int hex_chars = 0;
    for (char c : main_part) {
        if (std::isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            hex_chars++;
        }
    }

    double hex_ratio = static_cast<double>(hex_chars) / main_part.length();
    if (hex_ratio > 0.9 && main_part.length() > 32) {
        return true;
    }

    return false;
}

// ============================================================================
// 协议异常检测
// ============================================================================

bool DnsAnomalyDetector::has_protocol_error(const DnsMessage& message) const {
    if (!message.is_response()) {
        return false;
    }

    // 检查错误响应代码
    DnsResponseCode rcode = message.flags.rcode;
    return rcode == DnsResponseCode::FORMERR ||
           rcode == DnsResponseCode::SERVFAIL ||
           rcode == DnsResponseCode::NOTIMP ||
           rcode == DnsResponseCode::REFUSED;
}

bool DnsAnomalyDetector::has_unusual_query_type(const DnsMessage& message) const {
    // 常见查询类型：A, AAAA, CNAME, MX, TXT, NS, PTR, SOA, SRV
    const std::unordered_set<DnsRecordType> common_types = {
        DnsRecordType::A,
        DnsRecordType::AAAA,
        DnsRecordType::CNAME,
        DnsRecordType::MX,
        DnsRecordType::TXT,
        DnsRecordType::NS,
        DnsRecordType::PTR,
        DnsRecordType::SOA,
        DnsRecordType::SRV,
        DnsRecordType::ANY
    };

    for (const auto& question : message.questions) {
        if (common_types.find(question.qtype) == common_types.end()) {
            // 特别注意 NULL 类型（常用于隧道）
            if (question.qtype == DnsRecordType::NULL_RECORD) {
                return true;
            }
            // 其他罕见类型
            return true;
        }
    }

    return false;
}

// ============================================================================
// 可疑行为检测
// ============================================================================

bool DnsAnomalyDetector::has_blacklisted_ip(const DnsMessage& message) const {
    if (!message.is_response()) {
        return false;
    }

    for (const auto& answer : message.answers) {
        std::string ip = answer.get_ip_address();
        if (!ip.empty() && config_.blacklisted_ips.count(ip) > 0) {
            return true;
        }
    }

    return false;
}

bool DnsAnomalyDetector::has_suspicious_tld(const std::string& domain) const {
    std::string tld = extract_tld(domain);
    return config_.suspicious_tlds.count(tld) > 0;
}

bool DnsAnomalyDetector::has_zero_ttl(const DnsMessage& message) const {
    if (!message.is_response()) {
        return false;
    }

    for (const auto& answer : message.answers) {
        if (answer.ttl == 0) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// 辅助方法
// ============================================================================

double DnsAnomalyDetector::calculate_entropy(const std::string& str) const {
    if (str.empty()) return 0.0;

    // 计算字符频率
    std::unordered_map<char, int> freq;
    for (char c : str) {
        // 转换为小写统一处理
        char lc = std::tolower(c);
        freq[lc]++;
    }

    // 计算香农熵
    double entropy = 0.0;
    for (const auto& pair : freq) {
        double p = static_cast<double>(pair.second) / str.length();
        entropy -= p * std::log2(p);
    }

    return entropy;
}

int DnsAnomalyDetector::count_subdomain_levels(const std::string& domain) const {
    if (domain.empty()) return 0;

    int count = 0;
    for (char c : domain) {
        if (c == '.') {
            count++;
        }
    }

    return count;
}

double DnsAnomalyDetector::calculate_numeric_ratio(const std::string& str) const {
    if (str.empty()) return 0.0;

    int numeric_count = 0;
    int total_count = 0;

    for (char c : str) {
        if (c != '.') {  // 忽略点
            total_count++;
            if (std::isdigit(c)) {
                numeric_count++;
            }
        }
    }

    if (total_count == 0) return 0.0;

    return static_cast<double>(numeric_count) / total_count;
}

std::string DnsAnomalyDetector::extract_tld(const std::string& domain) const {
    size_t last_dot = domain.rfind('.');
    if (last_dot == std::string::npos) {
        return "";
    }
    return domain.substr(last_dot);  // 包含点，如 ".tk"
}

} // namespace decoders
} // namespace netguardian
