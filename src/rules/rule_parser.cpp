#include "rules/rule_parser.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace netguardian {
namespace rules {

std::string ParseError::to_string() const {
    std::ostringstream oss;
    oss << "Error";
    if (line_number > 0) {
        oss << " at line " << line_number;
        if (column > 0) oss << ", column " << column;
    }
    oss << ": " << message;
    if (!line_text.empty()) {
        oss << "\n  " << line_text;
    }
    return oss.str();
}

// 解析单条规则
RulePtr RuleParser::parse_rule(const std::string& rule_text) {
    // 跳过空行和注释
    std::string trimmed = trim(rule_text);
    if (trimmed.empty() || trimmed[0] == '#') {
        return nullptr;
    }

    auto rule = std::make_shared<Rule>();
    rule->set_raw_text(rule_text);

    // 分割规则头部和选项
    std::string header_text, options_text;
    if (!split_rule(trimmed, header_text, options_text)) {
        add_error("Invalid rule format", rule_text);
        total_failed_++;
        return nullptr;
    }

    // 解析头部
    if (!parse_header(header_text, rule->header())) {
        add_error("Failed to parse rule header", rule_text);
        total_failed_++;
        return nullptr;
    }

    // 解析选项
    if (!options_text.empty()) {
        if (!parse_options(options_text, *rule)) {
            add_error("Failed to parse rule options", rule_text);
            total_failed_++;
            return nullptr;
        }
    }

    total_parsed_++;
    return rule;
}

// 解析规则文件
std::vector<RulePtr> RuleParser::parse_file(const std::string& filename) {
    std::vector<RulePtr> rules;
    std::ifstream file(filename);

    if (!file.is_open()) {
        add_error("Failed to open file: " + filename);
        return rules;
    }

    std::string line;
    current_line_ = 0;

    while (std::getline(file, line)) {
        current_line_++;
        auto rule = parse_rule(line);
        if (rule) {
            rules.push_back(rule);
        }
    }

    file.close();
    return rules;
}

// 解析多条规则（从字符串）
std::vector<RulePtr> RuleParser::parse_rules(const std::string& rules_text) {
    std::vector<RulePtr> rules;
    std::istringstream iss(rules_text);
    std::string line;
    current_line_ = 0;

    while (std::getline(iss, line)) {
        current_line_++;
        auto rule = parse_rule(line);
        if (rule) {
            rules.push_back(rule);
        }
    }

    return rules;
}

// 解析规则头部
bool RuleParser::parse_header(const std::string& header_text, RuleHeader& header) {
    auto tokens = split(header_text, ' ');
    if (tokens.size() < 7) {
        add_error("Incomplete rule header (expected at least 7 tokens)", header_text);
        return false;
    }

    // 解析动作
    header.action = string_to_action(tokens[0]);
    if (header.action == RuleAction::UNKNOWN) {
        add_error("Unknown action: " + tokens[0], header_text);
        return false;
    }

    // 解析协议
    header.protocol = string_to_protocol(tokens[1]);
    if (header.protocol == RuleProtocol::UNKNOWN) {
        add_error("Unknown protocol: " + tokens[1], header_text);
        return false;
    }

    // 解析源 IP
    if (!parse_ip(tokens[2], header.src_ip)) {
        add_error("Invalid source IP: " + tokens[2], header_text);
        return false;
    }

    // 解析源端口
    if (!parse_port(tokens[3], header.src_port)) {
        add_error("Invalid source port: " + tokens[3], header_text);
        return false;
    }

    // 解析方向
    header.direction = string_to_direction(tokens[4]);

    // 解析目标 IP
    if (!parse_ip(tokens[5], header.dst_ip)) {
        add_error("Invalid destination IP: " + tokens[5], header_text);
        return false;
    }

    // 解析目标端口
    if (!parse_port(tokens[6], header.dst_port)) {
        add_error("Invalid destination port: " + tokens[6], header_text);
        return false;
    }

    return true;
}

// 解析规则选项
bool RuleParser::parse_options(const std::string& options_text, Rule& rule) {
    // 去除首尾的括号
    std::string opts = trim(options_text);
    if (opts.empty()) return true;

    if (opts.front() == '(' && opts.back() == ')') {
        opts = opts.substr(1, opts.length() - 2);
    }

    // 分割选项（用分号分隔）
    size_t start = 0;
    size_t end = 0;
    bool in_quotes = false;

    while (end < opts.length()) {
        char c = opts[end];

        if (c == '"') {
            in_quotes = !in_quotes;
        } else if (c == ';' && !in_quotes) {
            std::string option_text = trim(opts.substr(start, end - start));
            if (!option_text.empty()) {
                RuleOption option(RuleOptionType::UNKNOWN, "");
                if (parse_option(option_text, option)) {
                    rule.add_option(option);
                }
            }
            start = end + 1;
        }

        end++;
    }

    // 处理最后一个选项
    if (start < opts.length()) {
        std::string option_text = trim(opts.substr(start));
        if (!option_text.empty()) {
            RuleOption option(RuleOptionType::UNKNOWN, "");
            if (parse_option(option_text, option)) {
                rule.add_option(option);
            }
        }
    }

    return true;
}

// 解析单个选项
bool RuleParser::parse_option(const std::string& option_text, RuleOption& option) {
    size_t colon_pos = option_text.find(':');

    if (colon_pos == std::string::npos) {
        // 没有值的选项（例如：nocase）
        option.name = trim(option_text);
        option.type = string_to_option_type(option.name);
        option.has_value = false;
        return true;
    }

    // 有值的选项
    option.name = trim(option_text.substr(0, colon_pos));
    option.type = string_to_option_type(option.name);

    std::string value = trim(option_text.substr(colon_pos + 1));

    // 去除引号
    if (value.length() >= 2 && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.length() - 2);
    }

    option.value = value;
    option.has_value = true;

    return true;
}

// 解析 IP 地址
bool RuleParser::parse_ip(const std::string& ip_text, IpAddress& ip) {
    std::string trimmed = trim(ip_text);

    if (trimmed == "any") {
        ip.is_any = true;
        ip.is_negated = false;
        return true;
    }

    // 检查取反
    if (trimmed[0] == '!') {
        ip.is_negated = true;
        trimmed = trim(trimmed.substr(1));
    } else {
        ip.is_negated = false;
    }

    ip.address = trimmed;
    ip.is_any = false;

    // TODO: 验证 IP 地址格式（IPv4/IPv6/CIDR）
    return true;
}

// 解析端口
bool RuleParser::parse_port(const std::string& port_text, PortRange& port) {
    std::string trimmed = trim(port_text);

    if (trimmed == "any") {
        port.is_any = true;
        port.is_negated = false;
        return true;
    }

    // 检查取反
    if (trimmed[0] == '!') {
        port.is_negated = true;
        trimmed = trim(trimmed.substr(1));
    } else {
        port.is_negated = false;
    }

    // 检查端口范围
    size_t colon_pos = trimmed.find(':');
    if (colon_pos != std::string::npos) {
        // 端口范围
        try {
            port.start = std::stoul(trimmed.substr(0, colon_pos));
            port.end = std::stoul(trimmed.substr(colon_pos + 1));
            port.is_any = false;
            return true;
        } catch (...) {
            return false;
        }
    } else {
        // 单个端口
        try {
            port.start = port.end = std::stoul(trimmed);
            port.is_any = false;
            return true;
        } catch (...) {
            return false;
        }
    }
}

// 去除空白
std::string RuleParser::trim(const std::string& str) {
    size_t start = 0;
    size_t end = str.length();

    while (start < end && std::isspace(str[start])) {
        start++;
    }

    while (end > start && std::isspace(str[end - 1])) {
        end--;
    }

    return str.substr(start, end - start);
}

// 分割字符串
std::vector<std::string> RuleParser::split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream iss(str);

    while (std::getline(iss, token, delimiter)) {
        token = trim(token);
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }

    return tokens;
}

// 分割规则（header 和 options）
bool RuleParser::split_rule(const std::string& rule_text, std::string& header, std::string& options) {
    size_t paren_pos = rule_text.find('(');

    if (paren_pos == std::string::npos) {
        // 没有选项
        header = trim(rule_text);
        options = "";
        return true;
    }

    header = trim(rule_text.substr(0, paren_pos));
    options = trim(rule_text.substr(paren_pos));

    return true;
}

// 添加错误
void RuleParser::add_error(const std::string& message, const std::string& line_text) {
    errors_.emplace_back(message, current_line_, 0, line_text);
}

} // namespace rules
} // namespace netguardian
