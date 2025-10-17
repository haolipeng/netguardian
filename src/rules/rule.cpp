#include "rules/rule.h"
#include <sstream>
#include <algorithm>
#include <arpa/inet.h>

namespace netguardian {
namespace rules {

// IpAddress 实现
std::string IpAddress::to_string() const {
    if (is_any) return "any";
    return (is_negated ? "!" : "") + address;
}

// PortRange 实现
bool PortRange::matches(uint16_t port) const {
    if (is_any) return true;
    bool match = (port >= start && port <= end);
    return is_negated ? !match : match;
}

std::string PortRange::to_string() const {
    if (is_any) return "any";

    std::string result;
    if (is_negated) result += "!";

    if (start == end) {
        result += std::to_string(start);
    } else {
        result += std::to_string(start) + ":" + std::to_string(end);
    }
    return result;
}

// RuleOption 实现
std::string RuleOption::to_string() const {
    if (has_value) {
        return name + ":\"" + value + "\"";
    }
    return name;
}

// RuleHeader 实现
std::string RuleHeader::to_string() const {
    std::ostringstream oss;
    oss << action_to_string(action) << " "
        << protocol_to_string(protocol) << " "
        << src_ip.to_string() << " "
        << src_port.to_string() << " "
        << direction_to_string(direction) << " "
        << dst_ip.to_string() << " "
        << dst_port.to_string();
    return oss.str();
}

// Rule 实现
void Rule::add_option(const RuleOption& option) {
    options_.push_back(option);

    // 更新元数据
    switch (option.type) {
        case RuleOptionType::MSG:
            message_ = option.value;
            break;
        case RuleOptionType::SID:
            sid_ = std::stoul(option.value);
            break;
        case RuleOptionType::REV:
            rev_ = std::stoul(option.value);
            break;
        case RuleOptionType::PRIORITY:
            priority_ = std::stoul(option.value);
            break;
        case RuleOptionType::CLASSTYPE:
            classtype_ = option.value;
            break;
        default:
            break;
    }
}

std::optional<RuleOption> Rule::get_option(RuleOptionType type) const {
    for (const auto& opt : options_) {
        if (opt.type == type) {
            return opt;
        }
    }
    return std::nullopt;
}

std::vector<RuleOption> Rule::get_options(RuleOptionType type) const {
    std::vector<RuleOption> result;
    for (const auto& opt : options_) {
        if (opt.type == type) {
            result.push_back(opt);
        }
    }
    return result;
}

std::string Rule::to_string() const {
    std::ostringstream oss;
    oss << header_.to_string() << " (";

    bool first = true;
    for (const auto& opt : options_) {
        if (!first) oss << "; ";
        oss << opt.to_string();
        first = false;
    }

    oss << ";)";
    return oss.str();
}

// 字符串转枚举
RuleAction string_to_action(const std::string& str) {
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower == "alert") return RuleAction::ALERT;
    if (lower == "log") return RuleAction::LOG;
    if (lower == "pass") return RuleAction::PASS;
    if (lower == "drop") return RuleAction::DROP;
    if (lower == "reject") return RuleAction::REJECT;

    return RuleAction::UNKNOWN;
}

RuleProtocol string_to_protocol(const std::string& str) {
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower == "tcp") return RuleProtocol::TCP;
    if (lower == "udp") return RuleProtocol::UDP;
    if (lower == "icmp") return RuleProtocol::ICMP;
    if (lower == "ip") return RuleProtocol::IP;
    if (lower == "any") return RuleProtocol::ANY;

    return RuleProtocol::UNKNOWN;
}

RuleDirection string_to_direction(const std::string& str) {
    if (str == "->") return RuleDirection::UNIDIRECTIONAL;
    if (str == "<>") return RuleDirection::BIDIRECTIONAL;

    return RuleDirection::UNIDIRECTIONAL;
}

RuleOptionType string_to_option_type(const std::string& str) {
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower == "msg") return RuleOptionType::MSG;
    if (lower == "content") return RuleOptionType::CONTENT;
    if (lower == "pcre") return RuleOptionType::PCRE;
    if (lower == "flags") return RuleOptionType::FLAGS;
    if (lower == "flow") return RuleOptionType::FLOW;
    if (lower == "sid") return RuleOptionType::SID;
    if (lower == "rev") return RuleOptionType::REV;
    if (lower == "priority") return RuleOptionType::PRIORITY;
    if (lower == "classtype") return RuleOptionType::CLASSTYPE;
    if (lower == "reference") return RuleOptionType::REFERENCE;
    if (lower == "threshold") return RuleOptionType::THRESHOLD;
    if (lower == "depth") return RuleOptionType::DEPTH;
    if (lower == "offset") return RuleOptionType::OFFSET;
    if (lower == "distance") return RuleOptionType::DISTANCE;
    if (lower == "within") return RuleOptionType::WITHIN;
    if (lower == "nocase") return RuleOptionType::NOCASE;
    if (lower == "rawbytes") return RuleOptionType::RAWBYTES;
    if (lower == "http_method") return RuleOptionType::HTTP_METHOD;
    if (lower == "http_uri") return RuleOptionType::HTTP_URI;
    if (lower == "http_header") return RuleOptionType::HTTP_HEADER;

    return RuleOptionType::UNKNOWN;
}

// 枚举转字符串
std::string action_to_string(RuleAction action) {
    switch (action) {
        case RuleAction::ALERT: return "alert";
        case RuleAction::LOG: return "log";
        case RuleAction::PASS: return "pass";
        case RuleAction::DROP: return "drop";
        case RuleAction::REJECT: return "reject";
        default: return "unknown";
    }
}

std::string protocol_to_string(RuleProtocol protocol) {
    switch (protocol) {
        case RuleProtocol::TCP: return "tcp";
        case RuleProtocol::UDP: return "udp";
        case RuleProtocol::ICMP: return "icmp";
        case RuleProtocol::IP: return "ip";
        case RuleProtocol::ANY: return "any";
        default: return "unknown";
    }
}

std::string direction_to_string(RuleDirection direction) {
    switch (direction) {
        case RuleDirection::UNIDIRECTIONAL: return "->";
        case RuleDirection::BIDIRECTIONAL: return "<>";
        default: return "->";
    }
}

std::string option_type_to_string(RuleOptionType type) {
    switch (type) {
        case RuleOptionType::MSG: return "msg";
        case RuleOptionType::CONTENT: return "content";
        case RuleOptionType::PCRE: return "pcre";
        case RuleOptionType::FLAGS: return "flags";
        case RuleOptionType::FLOW: return "flow";
        case RuleOptionType::SID: return "sid";
        case RuleOptionType::REV: return "rev";
        case RuleOptionType::PRIORITY: return "priority";
        case RuleOptionType::CLASSTYPE: return "classtype";
        case RuleOptionType::REFERENCE: return "reference";
        case RuleOptionType::THRESHOLD: return "threshold";
        case RuleOptionType::DEPTH: return "depth";
        case RuleOptionType::OFFSET: return "offset";
        case RuleOptionType::DISTANCE: return "distance";
        case RuleOptionType::WITHIN: return "within";
        case RuleOptionType::NOCASE: return "nocase";
        case RuleOptionType::RAWBYTES: return "rawbytes";
        case RuleOptionType::HTTP_METHOD: return "http_method";
        case RuleOptionType::HTTP_URI: return "http_uri";
        case RuleOptionType::HTTP_HEADER: return "http_header";
        default: return "unknown";
    }
}

} // namespace rules
} // namespace netguardian
