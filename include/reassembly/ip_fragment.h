#ifndef NETGUARDIAN_REASSEMBLY_IP_FRAGMENT_H
#define NETGUARDIAN_REASSEMBLY_IP_FRAGMENT_H

#include <cstdint>
#include <vector>
#include <chrono>
#include <memory>

namespace netguardian {
namespace reassembly {

// IP 分片节点
class IpFragment {
public:
    // 创建分片节点
    static IpFragment* create(uint16_t offset, const uint8_t* data, uint16_t len,
                              bool more_fragments,
                              const std::chrono::system_clock::time_point& timestamp);

    // 销毁分片节点
    void destroy();

    // 获取偏移量（字节）
    uint16_t offset() const { return offset_; }

    // 获取数据长度
    uint16_t length() const { return length_; }

    // 获取数据指针
    const uint8_t* data() const { return data_; }

    // 是否还有更多分片
    bool more_fragments() const { return more_fragments_; }

    // 获取结束偏移量
    uint16_t end_offset() const { return offset_ + length_; }

    // 时间戳
    const std::chrono::system_clock::time_point& timestamp() const { return timestamp_; }

    // 检查是否与另一个分片重叠
    bool overlaps_with(const IpFragment* other) const {
        return (offset_ < other->end_offset() && end_offset() > other->offset_);
    }

    // 链表指针
    IpFragment* next() const { return next_; }
    IpFragment* prev() const { return prev_; }
    void set_next(IpFragment* next) { next_ = next; }
    void set_prev(IpFragment* prev) { prev_ = prev; }

private:
    IpFragment(uint16_t offset, uint16_t len, bool more_fragments,
               const std::chrono::system_clock::time_point& timestamp)
        : offset_(offset)
        , length_(len)
        , more_fragments_(more_fragments)
        , timestamp_(timestamp)
        , next_(nullptr)
        , prev_(nullptr)
        , data_(nullptr)
    {}

    ~IpFragment() {
        if (data_) {
            delete[] data_;
        }
    }

    uint16_t offset_;           // 分片偏移量（字节）
    uint16_t length_;           // 数据长度
    bool more_fragments_;       // 是否还有更多分片（MF 标志）
    std::chrono::system_clock::time_point timestamp_;  // 接收时间
    IpFragment* next_;          // 下一个分片
    IpFragment* prev_;          // 前一个分片
    uint8_t* data_;             // 分片数据
};

// IP 分片统计信息
struct FragmentStatistics {
    uint32_t total_fragments;       // 总分片数
    uint32_t active_fragments;      // 活动分片数
    uint32_t reassembled_packets;   // 已重组数据包数
    uint32_t timeout_count;         // 超时次数
    uint32_t overlap_count;         // 重叠次数
    uint32_t out_of_order_count;    // 乱序次数

    FragmentStatistics()
        : total_fragments(0)
        , active_fragments(0)
        , reassembled_packets(0)
        , timeout_count(0)
        , overlap_count(0)
        , out_of_order_count(0)
    {}
};

} // namespace reassembly
} // namespace netguardian

#endif // NETGUARDIAN_REASSEMBLY_IP_FRAGMENT_H
