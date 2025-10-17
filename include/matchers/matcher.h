#ifndef NETGUARDIAN_MATCHERS_MATCHER_H
#define NETGUARDIAN_MATCHERS_MATCHER_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace netguardian {
namespace matchers {

// 匹配结果
struct MatchResult {
    bool matched;               // 是否匹配
    size_t offset;              // 匹配位置（字节偏移）
    size_t length;              // 匹配长度
    std::string matched_data;   // 匹配的数据

    MatchResult() : matched(false), offset(0), length(0) {}

    MatchResult(bool m, size_t off = 0, size_t len = 0, const std::string& data = "")
        : matched(m), offset(off), length(len), matched_data(data) {}
};

// 基础匹配器接口
class Matcher {
public:
    virtual ~Matcher() = default;

    // 执行匹配
    // data: 待匹配的数据
    // length: 数据长度
    // 返回：匹配结果
    virtual MatchResult match(const uint8_t* data, size_t length) const = 0;

    // 辅助函数：字符串版本
    MatchResult match(const std::string& data) const {
        return match(reinterpret_cast<const uint8_t*>(data.data()), data.length());
    }

    // 获取匹配器类型名称
    virtual std::string type() const = 0;

    // 获取匹配器描述
    virtual std::string description() const = 0;
};

using MatcherPtr = std::shared_ptr<Matcher>;

} // namespace matchers
} // namespace netguardian

#endif // NETGUARDIAN_MATCHERS_MATCHER_H
