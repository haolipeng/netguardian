#ifndef NETGUARDIAN_REASSEMBLY_TCP_SEGMENT_H
#define NETGUARDIAN_REASSEMBLY_TCP_SEGMENT_H

#include <cstdint>
#include <cstring>
#include <memory>
#include <chrono>

namespace netguardian {
namespace reassembly {

// 序列号比较宏（处理 32 位回绕）
#define SEQ_LT(a, b)  ((int32_t)((a) - (b)) < 0)
#define SEQ_LEQ(a, b) ((int32_t)((a) - (b)) <= 0)
#define SEQ_GT(a, b)  ((int32_t)((a) - (b)) > 0)
#define SEQ_GEQ(a, b) ((int32_t)((a) - (b)) >= 0)
#define SEQ_EQ(a, b)  ((int32_t)((a) - (b)) == 0)

// TCP 段节点
// 基于 Snort3 的设计，存储单个 TCP 段的数据
class TcpSegment {
public:
    // 创建新段
    static TcpSegment* create(uint32_t seq, const uint8_t* data, uint16_t len,
                              const std::chrono::system_clock::time_point& timestamp);

    // 释放段
    void destroy();

    // 获取段的起始序列号
    uint32_t start_seq() const { return seq_; }

    // 获取段的结束序列号（不包含）
    uint32_t end_seq() const { return seq_ + length_; }

    // 获取段数据长度
    uint16_t length() const { return length_; }

    // 获取段数据
    const uint8_t* data() const { return data_; }
    uint8_t* data() { return data_; }

    // 获取时间戳
    const std::chrono::system_clock::time_point& timestamp() const { return timestamp_; }

    // 检查是否与另一个段有重叠
    bool overlaps_with(const TcpSegment* other) const {
        return SEQ_LT(start_seq(), other->end_seq()) &&
               SEQ_LT(other->start_seq(), end_seq());
    }

    // 检查是否与序列号范围重叠
    bool overlaps_with_range(uint32_t seq_start, uint32_t seq_end) const {
        return SEQ_LT(start_seq(), seq_end) && SEQ_LT(seq_start, end_seq());
    }

    // 检查是否包含某个序列号
    bool contains_seq(uint32_t seq) const {
        return SEQ_GEQ(seq, start_seq()) && SEQ_LT(seq, end_seq());
    }

    // 检查下一个段是否连续（无 gap）
    bool is_contiguous_with_next() const {
        return next_ && SEQ_EQ(end_seq(), next_->start_seq());
    }

    // 链表指针
    TcpSegment* prev() const { return prev_; }
    TcpSegment* next() const { return next_; }

    void set_prev(TcpSegment* prev) { prev_ = prev; }
    void set_next(TcpSegment* next) { next_ = next; }

private:
    // 私有构造函数，只能通过 create() 创建
    TcpSegment(uint32_t seq, const uint8_t* data, uint16_t len,
               const std::chrono::system_clock::time_point& timestamp);

    ~TcpSegment();

    // 禁止拷贝
    TcpSegment(const TcpSegment&) = delete;
    TcpSegment& operator=(const TcpSegment&) = delete;

    uint32_t seq_;              // 段的起始序列号
    uint16_t length_;           // 段数据长度
    uint8_t* data_;             // 段数据（动态分配）

    std::chrono::system_clock::time_point timestamp_;  // 段到达时间

    TcpSegment* prev_;          // 前一个段
    TcpSegment* next_;          // 后一个段
};

} // namespace reassembly
} // namespace netguardian

#endif // NETGUARDIAN_REASSEMBLY_TCP_SEGMENT_H
