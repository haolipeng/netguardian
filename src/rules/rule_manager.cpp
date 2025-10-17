#include "rules/rule_manager.h"
#include <algorithm>

namespace netguardian {
namespace rules {

bool RuleManager::load_rules_file(const std::string& filename) {
    std::lock_guard<std::mutex> lock(mutex_);

    parser_.clear_errors();
    auto rules = parser_.parse_file(filename);

    for (auto& rule : rules) {
        if (rule && rule->sid() > 0) {
            rules_[rule->sid()] = rule;
        }
    }

    return !parser_.has_errors();
}

bool RuleManager::load_rules_string(const std::string& rules_text) {
    std::lock_guard<std::mutex> lock(mutex_);

    parser_.clear_errors();
    auto rules = parser_.parse_rules(rules_text);

    for (auto& rule : rules) {
        if (rule && rule->sid() > 0) {
            rules_[rule->sid()] = rule;
        }
    }

    return !parser_.has_errors();
}

bool RuleManager::add_rule(RulePtr rule) {
    if (!rule || rule->sid() == 0) {
        return false;
    }

    std::string error_msg;
    if (!validate_rule(*rule, error_msg)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    rules_[rule->sid()] = rule;
    return true;
}

RulePtr RuleManager::get_rule(uint32_t sid) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rules_.find(sid);
    if (it != rules_.end()) {
        return it->second;
    }

    return nullptr;
}

bool RuleManager::enable_rule(uint32_t sid) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rules_.find(sid);
    if (it != rules_.end()) {
        it->second->set_enabled(true);
        return true;
    }

    return false;
}

bool RuleManager::disable_rule(uint32_t sid) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rules_.find(sid);
    if (it != rules_.end()) {
        it->second->set_enabled(false);
        return true;
    }

    return false;
}

bool RuleManager::remove_rule(uint32_t sid) {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_.erase(sid) > 0;
}

void RuleManager::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.clear();
}

std::vector<RulePtr> RuleManager::get_all_rules() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RulePtr> result;
    result.reserve(rules_.size());

    for (const auto& pair : rules_) {
        result.push_back(pair.second);
    }

    return result;
}

std::vector<RulePtr> RuleManager::get_enabled_rules() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RulePtr> result;

    for (const auto& pair : rules_) {
        if (pair.second->enabled()) {
            result.push_back(pair.second);
        }
    }

    return result;
}

std::vector<RulePtr> RuleManager::get_rules_by_protocol(RuleProtocol protocol) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RulePtr> result;

    for (const auto& pair : rules_) {
        if (pair.second->header().protocol == protocol) {
            result.push_back(pair.second);
        }
    }

    return result;
}

std::vector<RulePtr> RuleManager::get_rules_by_action(RuleAction action) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RulePtr> result;

    for (const auto& pair : rules_) {
        if (pair.second->header().action == action) {
            result.push_back(pair.second);
        }
    }

    return result;
}

bool RuleManager::validate_rule(const Rule& rule, std::string& error_msg) const {
    // 验证 SID
    if (rule.sid() == 0) {
        error_msg = "Rule SID cannot be 0";
        return false;
    }

    // 验证动作
    if (rule.header().action == RuleAction::UNKNOWN) {
        error_msg = "Unknown rule action";
        return false;
    }

    // 验证协议
    if (rule.header().protocol == RuleProtocol::UNKNOWN) {
        error_msg = "Unknown protocol";
        return false;
    }

    // 验证至少有一个选项
    if (rule.options().empty()) {
        error_msg = "Rule must have at least one option";
        return false;
    }

    // 验证必须有 msg 选项
    if (rule.message().empty()) {
        error_msg = "Rule must have a 'msg' option";
        return false;
    }

    return true;
}

RuleStats RuleManager::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    RuleStats stats;
    stats.total_rules = rules_.size();

    for (const auto& pair : rules_) {
        const auto& rule = pair.second;

        if (rule->enabled()) {
            stats.enabled_rules++;
        } else {
            stats.disabled_rules++;
        }

        switch (rule->header().action) {
            case RuleAction::ALERT:
                stats.alert_rules++;
                break;
            case RuleAction::LOG:
                stats.log_rules++;
                break;
            case RuleAction::DROP:
                stats.drop_rules++;
                break;
            case RuleAction::PASS:
                stats.pass_rules++;
                break;
            default:
                break;
        }
    }

    return stats;
}

size_t RuleManager::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_.size();
}

bool RuleManager::empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_.empty();
}

} // namespace rules
} // namespace netguardian
