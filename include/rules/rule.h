#ifndef NETGUARDIAN_RULES_RULE_H
#define NETGUARDIAN_RULES_RULE_H

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include "utils/optional.h"

namespace netguardian {
namespace rules {

// 规则动作类型
enum class RuleAction {
    ALERT,      // 告警并记录
    LOG,        // 仅记录
    PASS,       // 放行（不检测）
    DROP,       // 丢弃（需要内联模式）
    REJECT,     // 拒绝并发送 RST/ICMP
    UNKNOWN
};

// 协议类型
enum class RuleProtocol {
    TCP,
    UDP,
    ICMP,
    IP,         // 任何 IP 协议
    ANY,        // 任何协议
    UNKNOWN
};

// 规则方向
enum class RuleDirection {
    UNIDIRECTIONAL,    // -> 单向
    BIDIRECTIONAL      // <> 双向
};

// IP 地址匹配类型
struct IpAddress {
    std::string address;    // IP 地址或 CIDR (例如：192.168.1.0/24)
    bool is_any;            // 是否为 "any"
    bool is_negated;        // 是否为取反 (!)

    IpAddress() : is_any(true), is_negated(false) {}
    explicit IpAddress(const std::string& addr)
        : address(addr), is_any(addr == "any"), is_negated(false) {}

    std::string to_string() const;
};

// 端口匹配类型
struct PortRange {
    uint16_t start;         // 起始端口
    uint16_t end;           // 结束端口（如果是单端口，end == start）
    bool is_any;            // 是否为 "any"
    bool is_negated;        // 是否为取反 (!)

    PortRange() : start(0), end(0), is_any(true), is_negated(false) {}
    explicit PortRange(uint16_t port)
        : start(port), end(port), is_any(false), is_negated(false) {}
    PortRange(uint16_t s, uint16_t e)
        : start(s), end(e), is_any(false), is_negated(false) {}

    bool matches(uint16_t port) const;
    std::string to_string() const;
};

// 规则选项类型
enum class RuleOptionType {
    MSG,            // 消息
    CONTENT,        // 内容匹配
    PCRE,           // 正则表达式
    FLAGS,          // TCP 标志
    FLOW,           // 流方向
    SID,            // 规则 ID
    REV,            // 规则版本
    PRIORITY,       // 优先级
    CLASSTYPE,      // 分类
    REFERENCE,      // 参考链接
    THRESHOLD,      // 阈值
    DEPTH,          // 搜索深度
    OFFSET,         // 偏移量
    DISTANCE,       // 距离
    WITHIN,         // 范围内
    NOCASE,         // 忽略大小写
    RAWBYTES,       // 原始字节
    HTTP_METHOD,    // HTTP 方法
    HTTP_URI,       // HTTP URI
    HTTP_HEADER,    // HTTP 头部
    UNKNOWN
};

// 规则选项
struct RuleOption {
    RuleOptionType type;
    std::string name;           // 选项名称
    std::string value;          // 选项值
    bool has_value;             // 是否有值

    RuleOption(RuleOptionType t, const std::string& n)
        : type(t), name(n), has_value(false) {}

    RuleOption(RuleOptionType t, const std::string& n, const std::string& v)
        : type(t), name(n), value(v), has_value(true) {}

    std::string to_string() const;
};

// 规则头部（规则的基本匹配条件）
struct RuleHeader {
    RuleAction action;              // 动作
    RuleProtocol protocol;          // 协议
    IpAddress src_ip;               // 源 IP
    PortRange src_port;             // 源端口
    RuleDirection direction;        // 方向
    IpAddress dst_ip;               // 目标 IP
    PortRange dst_port;             // 目标端口

    RuleHeader()
        : action(RuleAction::ALERT)
        , protocol(RuleProtocol::IP)
        , direction(RuleDirection::UNIDIRECTIONAL)
    {}

    std::string to_string() const;
};

// 完整规则
class Rule {
public:
    Rule() : enabled_(true), sid_(0), rev_(1), priority_(3) {}

    // 规则头部
    const RuleHeader& header() const { return header_; }
    RuleHeader& header() { return header_; }

    // 规则选项
    const std::vector<RuleOption>& options() const { return options_; }
    void add_option(const RuleOption& option);

    // 规则元数据
    uint32_t sid() const { return sid_; }
    void set_sid(uint32_t sid) { sid_ = sid; }

    uint32_t rev() const { return rev_; }
    void set_rev(uint32_t rev) { rev_ = rev; }

    const std::string& message() const { return message_; }
    void set_message(const std::string& msg) { message_ = msg; }

    uint32_t priority() const { return priority_; }
    void set_priority(uint32_t p) { priority_ = p; }

    const std::string& classtype() const { return classtype_; }
    void set_classtype(const std::string& ct) { classtype_ = ct; }

    bool enabled() const { return enabled_; }
    void set_enabled(bool enabled) { enabled_ = enabled; }

    // 获取特定类型的选项
    utils::optional<RuleOption> get_option(RuleOptionType type) const;
    std::vector<RuleOption> get_options(RuleOptionType type) const;

    // 规则字符串表示
    std::string to_string() const;

    // 规则原始文本（用于调试）
    const std::string& raw_text() const { return raw_text_; }
    void set_raw_text(const std::string& text) { raw_text_ = text; }

private:
    RuleHeader header_;                 // 规则头部
    std::vector<RuleOption> options_;   // 规则选项列表

    // 元数据（从选项中提取，方便访问）
    uint32_t sid_;                      // 规则 ID
    uint32_t rev_;                      // 规则版本
    std::string message_;               // 告警消息
    uint32_t priority_;                 // 优先级 (1-5, 1最高)
    std::string classtype_;             // 分类类型
    bool enabled_;                      // 是否启用

    std::string raw_text_;              // 原始规则文本
};

using RulePtr = std::shared_ptr<Rule>;

// 辅助函数：字符串转枚举
RuleAction string_to_action(const std::string& str);
RuleProtocol string_to_protocol(const std::string& str);
RuleDirection string_to_direction(const std::string& str);
RuleOptionType string_to_option_type(const std::string& str);

// 辅助函数：枚举转字符串
std::string action_to_string(RuleAction action);
std::string protocol_to_string(RuleProtocol protocol);
std::string direction_to_string(RuleDirection direction);
std::string option_type_to_string(RuleOptionType type);

} // namespace rules
} // namespace netguardian

#endif // NETGUARDIAN_RULES_RULE_H
