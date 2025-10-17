#ifndef NETGUARDIAN_REASSEMBLY_IPV6_REASSEMBLER_H
#define NETGUARDIAN_REASSEMBLY_IPV6_REASSEMBLER_H

#include "reassembly/ip_fragment.h"
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <array>

namespace netguardian {
namespace reassembly {

// IPv6 分片标识
struct Ipv6FragmentKey {
    std::array<uint8_t, 16> src_ip;     // 源 IPv6 地址
    std::array<uint8_t, 16> dst_ip;     // 目标 IPv6 地址
    uint32_t id;                        // 分片标识符

    bool operator==(const Ipv6FragmentKey& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               id == other.id;
    }
};

} // namespace reassembly
} // namespace netguardian

// Ipv6FragmentKey 的哈希函数
namespace std {
template <>
struct hash<netguardian::reassembly::Ipv6FragmentKey> {
    size_t operator()(const netguardian::reassembly::Ipv6FragmentKey& key) const {
        size_t h = 0;
        // 简化的哈希：只使用部分字节
        h ^= std::hash<uint32_t>{}(*reinterpret_cast<const uint32_t*>(key.src_ip.data()));
        h ^= std::hash<uint32_t>{}(*reinterpret_cast<const uint32_t*>(key.dst_ip.data())) << 1;
        h ^= std::hash<uint32_t>{}(key.id) << 2;
        return h;
    }
};
}

namespace netguardian {
namespace reassembly {

// IPv6 分片重组器（与 IPv4 类似）
class Ipv6Reassembler {
public:
    Ipv6Reassembler(uint32_t timeout_seconds = 60, uint32_t max_fragments = 100)
        : timeout_seconds_(timeout_seconds)
        , max_fragments_(max_fragments)
    {}

    ~Ipv6Reassembler() {
        clear_all();
    }

    // 添加分片
    bool add_fragment(const Ipv6FragmentKey& key,
                     uint16_t fragment_offset,
                     const uint8_t* data,
                     uint16_t data_len,
                     bool more_fragments);

    // 检查是否可以重组
    bool can_reassemble(const Ipv6FragmentKey& key) const;

    // 重组数据包
    std::vector<uint8_t> reassemble(const Ipv6FragmentKey& key);

    // 清理超时的分片
    void cleanup_timeout();

    // 清理所有分片
    void clear_all();

    // 获取统计信息
    const FragmentStatistics& stats() const { return stats_; }

private:
    struct FragmentList {
        IpFragment* head;
        IpFragment* tail;
        uint16_t total_length;
        bool has_last_fragment;
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

    std::unordered_map<Ipv6FragmentKey, FragmentList> fragment_cache_;

    void insert_fragment(FragmentList& list, IpFragment* frag);
    bool is_complete(const FragmentList& list) const;
    void clear_fragments(FragmentList& list);
};

} // namespace reassembly
} // namespace netguardian

#endif // NETGUARDIAN_REASSEMBLY_IPV6_REASSEMBLER_H
