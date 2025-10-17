#ifndef NETGUARDIAN_MATCHERS_CONTENT_MATCHER_H
#define NETGUARDIAN_MATCHERS_CONTENT_MATCHER_H

#include "matchers/matcher.h"
#include <array>
#include <algorithm>

namespace netguardian {
namespace matchers {

// Boyer-Moore 字符串匹配器
// 用于高效的单模式字符串匹配
class ContentMatcher : public Matcher {
public:
    // 构造函数
    // pattern: 要匹配的模式
    // case_sensitive: 是否区分大小写（默认区分）
    ContentMatcher(const std::string& pattern, bool case_sensitive = true)
        : pattern_(pattern)
        , case_sensitive_(case_sensitive)
    {
        if (!case_sensitive_) {
            // 转换为小写
            std::transform(pattern_.begin(), pattern_.end(), pattern_.begin(), ::tolower);
        }
        preprocess();
    }

    // 执行匹配
    MatchResult match(const uint8_t* data, size_t length) const override {
        if (pattern_.empty() || length < pattern_.length()) {
            return MatchResult(false);
        }

        // Boyer-Moore 算法
        size_t m = pattern_.length();
        size_t n = length;
        size_t s = 0;  // 模式串相对于文本串的偏移

        while (s <= n - m) {
            int j = static_cast<int>(m) - 1;

            // 从后向前匹配
            while (j >= 0) {
                uint8_t text_char = data[s + j];

                // 如果不区分大小写，转换为小写
                if (!case_sensitive_ && text_char >= 'A' && text_char <= 'Z') {
                    text_char = text_char + ('a' - 'A');
                }

                if (pattern_[j] != text_char) {
                    break;
                }
                j--;
            }

            if (j < 0) {
                // 匹配成功
                return MatchResult(
                    true,
                    s,
                    m,
                    std::string(reinterpret_cast<const char*>(data + s), m)
                );
            } else {
                // 使用坏字符规则计算移动距离
                uint8_t bad_char = data[s + j];
                if (!case_sensitive_ && bad_char >= 'A' && bad_char <= 'Z') {
                    bad_char = bad_char + ('a' - 'A');
                }

                int shift = j - bad_char_table_[bad_char];
                s += std::max(1, shift);
            }
        }

        return MatchResult(false);
    }

    std::string type() const override {
        return "ContentMatcher";
    }

    std::string description() const override {
        return "Boyer-Moore string matcher for pattern: \"" + pattern_ + "\"" +
               (case_sensitive_ ? "" : " (case-insensitive)");
    }

    const std::string& pattern() const { return pattern_; }
    bool is_case_sensitive() const { return case_sensitive_; }

private:
    std::string pattern_;                   // 匹配模式
    bool case_sensitive_;                   // 是否区分大小写
    std::array<int, 256> bad_char_table_;   // 坏字符表

    // 预处理：构建坏字符表
    void preprocess() {
        // 初始化坏字符表为 -1
        bad_char_table_.fill(-1);

        // 填充坏字符表
        for (size_t i = 0; i < pattern_.length(); ++i) {
            bad_char_table_[static_cast<uint8_t>(pattern_[i])] = static_cast<int>(i);
        }
    }
};

} // namespace matchers
} // namespace netguardian

#endif // NETGUARDIAN_MATCHERS_CONTENT_MATCHER_H
