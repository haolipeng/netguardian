#ifndef NETGUARDIAN_RULES_RULE_PARSER_H
#define NETGUARDIAN_RULES_RULE_PARSER_H

#include "rules/rule.h"
#include <string>
#include <vector>
#include <memory>

namespace netguardian {
namespace rules {

// 解析错误
struct ParseError {
    std::string message;        // 错误消息
    size_t line_number;         // 行号
    size_t column;              // 列号
    std::string line_text;      // 错误行文本

    ParseError(const std::string& msg, size_t line = 0, size_t col = 0, const std::string& text = "")
        : message(msg), line_number(line), column(col), line_text(text) {}

    std::string to_string() const;
};

// 规则解析器
class RuleParser {
public:
    RuleParser() : current_line_(0) {}

    // 解析单条规则
    // 返回：规则指针，如果解析失败返回 nullptr
    RulePtr parse_rule(const std::string& rule_text);

    // 解析规则文件
    // 返回：规则列表
    std::vector<RulePtr> parse_file(const std::string& filename);

    // 解析多条规则（从字符串）
    std::vector<RulePtr> parse_rules(const std::string& rules_text);

    // 获取最后的错误
    const std::vector<ParseError>& errors() const { return errors_; }
    bool has_errors() const { return !errors_.empty(); }
    void clear_errors() { errors_.clear(); }

    // 获取统计信息
    size_t total_parsed() const { return total_parsed_; }
    size_t total_failed() const { return total_failed_; }

private:
    std::vector<ParseError> errors_;    // 错误列表
    size_t current_line_;               // 当前行号
    size_t total_parsed_;               // 成功解析的规则数
    size_t total_failed_;               // 失败的规则数

    // 解析规则头部
    bool parse_header(const std::string& header_text, RuleHeader& header);

    // 解析规则选项
    bool parse_options(const std::string& options_text, Rule& rule);

    // 解析单个选项
    bool parse_option(const std::string& option_text, RuleOption& option);

    // 解析 IP 地址
    bool parse_ip(const std::string& ip_text, IpAddress& ip);

    // 解析端口
    bool parse_port(const std::string& port_text, PortRange& port);

    // 辅助函数：去除空白
    std::string trim(const std::string& str);

    // 辅助函数：分割字符串
    std::vector<std::string> split(const std::string& str, char delimiter);

    // 辅助函数：分割规则（header 和 options）
    bool split_rule(const std::string& rule_text, std::string& header, std::string& options);

    // 添加错误
    void add_error(const std::string& message, const std::string& line_text = "");
};

} // namespace rules
} // namespace netguardian

#endif // NETGUARDIAN_RULES_RULE_PARSER_H
