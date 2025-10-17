#ifndef NETGUARDIAN_MATCHERS_PCRE_MATCHER_H
#define NETGUARDIAN_MATCHERS_PCRE_MATCHER_H

#include "matchers/matcher.h"
#include <regex>

namespace netguardian {
namespace matchers {

// 正则表达式匹配器
// 使用 C++ std::regex 进行模式匹配
class PcreMatcher : public Matcher {
public:
    // 构造函数
    // pattern: 正则表达式模式
    // case_sensitive: 是否区分大小写（默认区分）
    PcreMatcher(const std::string& pattern, bool case_sensitive = true)
        : pattern_(pattern)
        , case_sensitive_(case_sensitive)
    {
        try {
            auto flags = std::regex::ECMAScript;
            if (!case_sensitive_) {
                flags |= std::regex::icase;
            }
            regex_ = std::regex(pattern_, flags);
            valid_ = true;
        } catch (const std::regex_error& e) {
            valid_ = false;
            error_msg_ = e.what();
        }
    }

    // 执行匹配
    MatchResult match(const uint8_t* data, size_t length) const override {
        if (!valid_) {
            return MatchResult(false);
        }

        std::string text(reinterpret_cast<const char*>(data), length);
        std::smatch match;

        if (std::regex_search(text, match, regex_)) {
            return MatchResult(
                true,
                match.position(0),
                match.length(0),
                match.str(0)
            );
        }

        return MatchResult(false);
    }

    // 查找所有匹配
    std::vector<MatchResult> match_all(const uint8_t* data, size_t length) const {
        std::vector<MatchResult> results;

        if (!valid_) {
            return results;
        }

        std::string text(reinterpret_cast<const char*>(data), length);
        auto begin = std::sregex_iterator(text.begin(), text.end(), regex_);
        auto end = std::sregex_iterator();

        for (std::sregex_iterator i = begin; i != end; ++i) {
            std::smatch match = *i;
            results.emplace_back(
                true,
                match.position(0),
                match.length(0),
                match.str(0)
            );
        }

        return results;
    }

    std::string type() const override {
        return "PcreMatcher";
    }

    std::string description() const override {
        if (!valid_) {
            return "Invalid regex pattern: \"" + pattern_ + "\" (" + error_msg_ + ")";
        }
        return "Regex matcher for pattern: \"" + pattern_ + "\"" +
               (case_sensitive_ ? "" : " (case-insensitive)");
    }

    const std::string& pattern() const { return pattern_; }
    bool is_valid() const { return valid_; }
    bool is_case_sensitive() const { return case_sensitive_; }
    const std::string& error_message() const { return error_msg_; }

private:
    std::string pattern_;       // 正则表达式模式
    bool case_sensitive_;       // 是否区分大小写
    std::regex regex_;          // 编译后的正则表达式
    bool valid_;                // 是否有效
    std::string error_msg_;     // 错误消息
};

} // namespace matchers
} // namespace netguardian

#endif // NETGUARDIAN_MATCHERS_PCRE_MATCHER_H
