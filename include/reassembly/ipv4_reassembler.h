#ifndef NETGUARDIAN_REASSEMBLY_IPV4_REASSEMBLER_H
#define NETGUARDIAN_REASSEMBLY_IPV4_REASSEMBLER_H

#include "reassembly/ip_fragment.h"
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <chrono>

namespace netguardian {
namespace reassembly {

// IPv4 分片标识（用于匹配同一数据包的分片）
struct Ipv4FragmentKey {
    uint32_t src_ip;        // 源 IP（网络字节序）
    uint32_t dst_ip;        // 目标 IP（网络字节序）
    uint16_t id;            // IP 标识符
    uint8_t protocol;       // 协议

    bool operator==(const Ipv4FragmentKey& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               id == other.id &&
               protocol == other.protocol;
    }
};

} // namespace reassembly
} // namespace netguardian

// Ipv4FragmentKey 的哈希函数
namespace std {
template <>
struct hash<netguardian::reassembly::Ipv4FragmentKey> {
    size_t operator()(const netguardian::reassembly::Ipv4FragmentKey& key) const {
        size_t h1 = std::hash<uint32_t>{}(key.src_ip);
        size_t h2 = std::hash<uint32_t>{}(key.dst_ip);
        size_t h3 = std::hash<uint16_t>{}(key.id);
        size_t h4 = std::hash<uint8_t>{}(key.protocol);
        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
    }
};
}

namespace netguardian {
namespace reassembly {

// IPv4 分片重组器
class Ipv4Reassembler {
public:
    Ipv4Reassembler(uint32_t timeout_seconds = 60, uint32_t max_fragments = 100)
        : timeout_seconds_(timeout_seconds)
        , max_fragments_(max_fragments)
    {}

    ~Ipv4Reassembler() {
        clear_all();
    }

    // 添加分片
    // 返回 true 表示分片已接收，false 表示出错或重复
    bool add_fragment(const Ipv4FragmentKey& key,
                     uint16_t fragment_offset,  // 分片偏移量（字节）
                     const uint8_t* data,
                     uint16_t data_len,
                     bool more_fragments);

    // 检查是否可以重组（所有分片都已到达）
    bool can_reassemble(const Ipv4FragmentKey& key) const;

    // 重组数据包
    // 返回重组后的完整 IP 负载
    std::vector<uint8_t> reassemble(const Ipv4FragmentKey& key);

    // 清理超时的分片
    void cleanup_timeout();

    // 清理所有分片
    void clear_all();

    // 获取统计信息
    const FragmentStatistics& stats() const { return stats_; }

private:
    // 分片链表
    struct FragmentList {
        IpFragment* head;
        IpFragment* tail;
        uint16_t total_length;      // 已知的总长度（从最后一个分片获取）
        bool has_last_fragment;     // 是否收到最后一个分片
        std::chrono::system_clock::time_point first_seen;

        FragmentList()
            : head(nullptr)
            , tail(nullptr)
            , total_length(0)
            , has_last_fragment(false)
            , first_seen(std::chrono::system_clock::now())
        {}
    };

    uint32_t timeout_seconds_;
    uint32_t max_fragments_;
    FragmentStatistics stats_;

    // 分片缓存：key -> 分片链表
    std::unordered_map<Ipv4FragmentKey, FragmentList> fragment_cache_;

    // 插入分片到链表（按偏移量排序）
    void insert_fragment(FragmentList& list, IpFragment* frag);

    // 检查分片是否完整
    bool is_complete(const FragmentList& list) const;

    // 清理分片链表
    void clear_fragments(FragmentList& list);
};

} // namespace reassembly
} // namespace netguardian

#endif // NETGUARDIAN_REASSEMBLY_IPV4_REASSEMBLER_H
