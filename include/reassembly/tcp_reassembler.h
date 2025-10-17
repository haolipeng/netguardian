#ifndef NETGUARDIAN_REASSEMBLY_TCP_REASSEMBLER_H
#define NETGUARDIAN_REASSEMBLY_TCP_REASSEMBLER_H

#include "reassembly/tcp_segment.h"
#include <vector>
#include <cstdint>
#include <chrono>

namespace netguardian {
namespace reassembly {

// 重叠处理策略
enum class OverlapPolicy {
    FIRST,      // 保留先到的数据（Linux 风格）
    LAST,       // 保留后到的数据（Windows 风格）
};

// 重组统计信息
struct ReassemblyStats {
    uint32_t total_segments;        // 总段数
    uint32_t active_segments;       // 当前队列中的段数
    uint32_t total_bytes;           // 总字节数
    uint32_t reassembled_bytes;     // 已重组字节数
    uint32_t overlap_count;         // 重叠次数
    uint32_t out_of_order_count;    // 乱序次数
    uint32_t gap_count;             // 数据空洞次数

    ReassemblyStats()
        : total_segments(0), active_segments(0), total_bytes(0)
        , reassembled_bytes(0), overlap_count(0)
        , out_of_order_count(0), gap_count(0)
    {}
};

// TCP 重组器
// 管理 TCP 段的队列，处理乱序、重叠、重传等问题
class TcpReassembler {
public:
    // 构造函数
    explicit TcpReassembler(OverlapPolicy policy = OverlapPolicy::FIRST);

    // 析构函数
    ~TcpReassembler();

    // 添加新的 TCP 段
    // 返回：是否成功添加
    bool add_segment(uint32_t seq, const uint8_t* data, uint16_t len);

    // 获取已重组的连续数据
    // next_seq: 返回下一个期望的序列号
    // 返回：重组后的连续数据（从 base_seq 开始）
    std::vector<uint8_t> get_reassembled_data(uint32_t& next_seq);

    // 清除已确认的数据（小于 ack_seq 的段）
    void purge_acked_data(uint32_t ack_seq);

    // 清空所有数据
    void clear();

    // 获取统计信息
    const ReassemblyStats& stats() const { return stats_; }

    // 设置基准序列号（第一个段的序列号）
    void set_base_seq(uint32_t seq) { base_seq_ = seq; }

    // 获取基准序列号
    uint32_t base_seq() const { return base_seq_; }

    // 获取下一个期望的序列号
    uint32_t next_expected_seq() const { return next_expected_seq_; }

    // 检查是否有数据可用
    bool has_data() const { return head_ != nullptr; }

    // 检查是否有连续的数据可以刷新
    bool has_contiguous_data() const;

    // 设置最大缓存大小（字节）
    void set_max_bytes(size_t max_bytes) { max_bytes_ = max_bytes; }

    // 设置最大段数
    void set_max_segments(size_t max_segments) { max_segments_ = max_segments; }

private:
    // 插入段到队列
    void insert_segment(TcpSegment* seg);

    // 查找插入位置
    TcpSegment* find_insert_position(uint32_t seq);

    // 处理重叠
    void handle_overlap(TcpSegment* new_seg);

    // 移除段
    void remove_segment(TcpSegment* seg);

    // 检查是否超过限制
    bool is_over_limit() const;

    // 清除最旧的段
    void purge_oldest_segments();

    TcpSegment* head_;              // 队列头（最小序列号）
    TcpSegment* tail_;              // 队列尾（最大序列号）

    uint32_t base_seq_;             // 基准序列号（第一个段）
    uint32_t next_expected_seq_;    // 下一个期望的序列号

    OverlapPolicy policy_;          // 重叠处理策略
    ReassemblyStats stats_;         // 统计信息

    size_t max_bytes_;              // 最大缓存字节数
    size_t max_segments_;           // 最大段数
};

} // namespace reassembly
} // namespace netguardian

#endif // NETGUARDIAN_REASSEMBLY_TCP_REASSEMBLER_H
