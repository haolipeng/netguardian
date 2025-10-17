#ifndef NETGUARDIAN_MATCHERS_MULTI_PATTERN_MATCHER_H
#define NETGUARDIAN_MATCHERS_MULTI_PATTERN_MATCHER_H

#include "matchers/matcher.h"
#include <unordered_map>
#include <queue>
#include <cctype>

namespace netguardian {
namespace matchers {

// Aho-Corasick 多模式匹配器
// 用于同时匹配多个模式串
class MultiPatternMatcher : public Matcher {
public:
    // 构造函数
    MultiPatternMatcher(bool case_sensitive = true)
        : case_sensitive_(case_sensitive)
        , next_state_(1)
    {
        // 初始化根节点
        root_.next.clear();
        root_.fail = nullptr;
        root_.output.clear();
    }

    // 添加模式串
    void add_pattern(const std::string& pattern) {
        if (pattern.empty()) return;

        std::string pat = pattern;
        if (!case_sensitive_) {
            std::transform(pat.begin(), pat.end(), pat.begin(), ::tolower);
        }

        patterns_.push_back(pat);
        insert_pattern(pat);
    }

    // 添加多个模式串
    void add_patterns(const std::vector<std::string>& patterns) {
        for (const auto& pattern : patterns) {
            add_pattern(pattern);
        }
    }

    // 构建失败指针（必须在添加完所有模式后调用）
    void build() {
        build_failure_links();
        built_ = true;
    }

    // 执行匹配（返回第一个匹配）
    MatchResult match(const uint8_t* data, size_t length) const override {
        if (!built_ || patterns_.empty()) {
            return MatchResult(false);
        }

        const TrieNode* current = &root_;

        for (size_t i = 0; i < length; ++i) {
            uint8_t ch = data[i];

            // 如果不区分大小写，转换为小写
            if (!case_sensitive_ && ch >= 'A' && ch <= 'Z') {
                ch = ch + ('a' - 'A');
            }

            // 沿着失败指针查找匹配
            while (current != &root_ && current->next.find(ch) == current->next.end()) {
                current = current->fail;
            }

            if (current->next.find(ch) != current->next.end()) {
                current = current->next.at(ch);
            }

            // 检查是否有输出
            if (!current->output.empty()) {
                const std::string& matched_pattern = current->output.front();
                size_t offset = i + 1 - matched_pattern.length();

                return MatchResult(
                    true,
                    offset,
                    matched_pattern.length(),
                    std::string(reinterpret_cast<const char*>(data + offset), matched_pattern.length())
                );
            }
        }

        return MatchResult(false);
    }

    // 查找所有匹配
    std::vector<MatchResult> match_all(const uint8_t* data, size_t length) const {
        std::vector<MatchResult> results;

        if (!built_ || patterns_.empty()) {
            return results;
        }

        const TrieNode* current = &root_;

        for (size_t i = 0; i < length; ++i) {
            uint8_t ch = data[i];

            // 如果不区分大小写，转换为小写
            if (!case_sensitive_ && ch >= 'A' && ch <= 'Z') {
                ch = ch + ('a' - 'A');
            }

            // 沿着失败指针查找匹配
            while (current != &root_ && current->next.find(ch) == current->next.end()) {
                current = current->fail;
            }

            if (current->next.find(ch) != current->next.end()) {
                current = current->next.at(ch);
            }

            // 收集所有输出
            const TrieNode* temp = current;
            while (temp != &root_) {
                for (const auto& pattern : temp->output) {
                    size_t offset = i + 1 - pattern.length();
                    results.emplace_back(
                        true,
                        offset,
                        pattern.length(),
                        std::string(reinterpret_cast<const char*>(data + offset), pattern.length())
                    );
                }

                temp = temp->fail;
                if (temp == nullptr) break;
            }
        }

        return results;
    }

    std::string type() const override {
        return "MultiPatternMatcher";
    }

    std::string description() const override {
        return "Aho-Corasick multi-pattern matcher with " + std::to_string(patterns_.size()) +
               " patterns" + (case_sensitive_ ? "" : " (case-insensitive)");
    }

    const std::vector<std::string>& patterns() const { return patterns_; }
    bool is_case_sensitive() const { return case_sensitive_; }

private:
    // Trie 节点
    struct TrieNode {
        std::unordered_map<uint8_t, TrieNode*> next;  // 子节点
        TrieNode* fail;                                // 失败指针
        std::vector<std::string> output;               // 输出（匹配的模式）
    };

    mutable TrieNode root_;                 // 根节点
    std::vector<std::string> patterns_;     // 模式列表
    bool case_sensitive_;                   // 是否区分大小写
    bool built_ = false;                    // 是否已构建失败指针
    int next_state_;                        // 下一个状态 ID

    // 插入模式串到 Trie
    void insert_pattern(const std::string& pattern) {
        TrieNode* current = &root_;

        for (char ch : pattern) {
            uint8_t c = static_cast<uint8_t>(ch);

            if (current->next.find(c) == current->next.end()) {
                current->next[c] = new TrieNode();
                current->next[c]->fail = nullptr;
            }

            current = current->next[c];
        }

        current->output.push_back(pattern);
    }

    // 构建失败指针（BFS）
    void build_failure_links() {
        std::queue<TrieNode*> queue;

        // 初始化第一层节点的失败指针指向根节点
        for (auto& pair : root_.next) {
            pair.second->fail = &root_;
            queue.push(pair.second);
        }

        // BFS 构建失败指针
        while (!queue.empty()) {
            TrieNode* current = queue.front();
            queue.pop();

            for (auto& pair : current->next) {
                uint8_t ch = pair.first;
                TrieNode* child = pair.second;

                queue.push(child);

                // 查找失败指针
                TrieNode* fail_node = current->fail;

                while (fail_node != nullptr && fail_node != &root_ &&
                       fail_node->next.find(ch) == fail_node->next.end()) {
                    fail_node = fail_node->fail;
                }

                if (fail_node != nullptr && fail_node->next.find(ch) != fail_node->next.end()) {
                    child->fail = fail_node->next[ch];
                } else {
                    child->fail = &root_;
                }

                // 合并输出
                if (child->fail != &root_ && !child->fail->output.empty()) {
                    child->output.insert(
                        child->output.end(),
                        child->fail->output.begin(),
                        child->fail->output.end()
                    );
                }
            }
        }
    }
};

} // namespace matchers
} // namespace netguardian

#endif // NETGUARDIAN_MATCHERS_MULTI_PATTERN_MATCHER_H
