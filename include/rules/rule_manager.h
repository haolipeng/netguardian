#ifndef NETGUARDIAN_RULES_RULE_MANAGER_H
#define NETGUARDIAN_RULES_RULE_MANAGER_H

#include "rules/rule.h"
#include "rules/rule_parser.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>

namespace netguardian {
namespace rules {

// 规则统计信息
struct RuleStats {
    size_t total_rules;         // 总规则数
    size_t enabled_rules;       // 启用的规则数
    size_t disabled_rules;      // 禁用的规则数
    size_t alert_rules;         // 告警规则数
    size_t log_rules;           // 日志规则数
    size_t drop_rules;          // 丢弃规则数
    size_t pass_rules;          // 放行规则数

    RuleStats()
        : total_rules(0), enabled_rules(0), disabled_rules(0)
        , alert_rules(0), log_rules(0), drop_rules(0), pass_rules(0)
    {}
};

// 规则管理器
class RuleManager {
public:
    RuleManager() = default;

    // 加载规则文件
    bool load_rules_file(const std::string& filename);

    // 加载规则字符串
    bool load_rules_string(const std::string& rules_text);

    // 添加单条规则
    bool add_rule(RulePtr rule);

    // 根据 SID 获取规则
    RulePtr get_rule(uint32_t sid) const;

    // 根据 SID 启用/禁用规则
    bool enable_rule(uint32_t sid);
    bool disable_rule(uint32_t sid);

    // 根据 SID 删除规则
    bool remove_rule(uint32_t sid);

    // 清空所有规则
    void clear();

    // 获取所有规则
    std::vector<RulePtr> get_all_rules() const;

    // 获取启用的规则
    std::vector<RulePtr> get_enabled_rules() const;

    // 根据协议获取规则
    std::vector<RulePtr> get_rules_by_protocol(RuleProtocol protocol) const;

    // 根据动作获取规则
    std::vector<RulePtr> get_rules_by_action(RuleAction action) const;

    // 验证规则
    bool validate_rule(const Rule& rule, std::string& error_msg) const;

    // 获取统计信息
    RuleStats get_stats() const;

    // 获取解析错误
    const std::vector<ParseError>& get_parse_errors() const {
        return parser_.errors();
    }

    // 规则数量
    size_t size() const;
    bool empty() const;

private:
    mutable std::mutex mutex_;                          // 互斥锁
    std::unordered_map<uint32_t, RulePtr> rules_;      // 规则表 (SID -> Rule)
    RuleParser parser_;                                 // 规则解析器

    // 更新统计信息（内部使用）
    void update_stats();
};

} // namespace rules
} // namespace netguardian

#endif // NETGUARDIAN_RULES_RULE_MANAGER_H
