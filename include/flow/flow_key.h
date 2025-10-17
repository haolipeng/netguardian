#ifndef NETGUARDIAN_FLOW_FLOW_KEY_H
#define NETGUARDIAN_FLOW_FLOW_KEY_H

#include <cstdint>
#include <functional>
#include <string>
#include <sstream>
#include <iomanip>

namespace netguardian {
namespace flow {

// 五元组流标识
struct FlowKey {
    uint32_t src_ip;      // 源 IP 地址（网络字节序）
    uint32_t dst_ip;      // 目标 IP 地址（网络字节序）
    uint16_t src_port;    // 源端口（主机字节序）
    uint16_t dst_port;    // 目标端口（主机字节序）
    uint8_t  protocol;    // 协议（6=TCP, 17=UDP）

    FlowKey()
        : src_ip(0), dst_ip(0), src_port(0), dst_port(0), protocol(0)
    {}

    FlowKey(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp, uint8_t proto)
        : src_ip(sip), dst_ip(dip), src_port(sp), dst_port(dp), protocol(proto)
    {}

    // 相等比较
    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }

    // 不等比较
    bool operator!=(const FlowKey& other) const {
        return !(*this == other);
    }

    // 小于比较（用于 std::map）
    bool operator<(const FlowKey& other) const {
        if (src_ip != other.src_ip) return src_ip < other.src_ip;
        if (dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
        if (src_port != other.src_port) return src_port < other.src_port;
        if (dst_port != other.dst_port) return dst_port < other.dst_port;
        return protocol < other.protocol;
    }

    // 获取反向流的 key（用于双向流关联）
    FlowKey reverse() const {
        return FlowKey(dst_ip, src_ip, dst_port, src_port, protocol);
    }

    // 转换为字符串（用于调试和日志）
    std::string to_string() const {
        std::ostringstream oss;

        // IP 地址转字符串
        uint8_t* sip = (uint8_t*)&src_ip;
        uint8_t* dip = (uint8_t*)&dst_ip;

        oss << static_cast<int>(sip[0]) << "."
            << static_cast<int>(sip[1]) << "."
            << static_cast<int>(sip[2]) << "."
            << static_cast<int>(sip[3]);

        oss << ":" << src_port << " -> ";

        oss << static_cast<int>(dip[0]) << "."
            << static_cast<int>(dip[1]) << "."
            << static_cast<int>(dip[2]) << "."
            << static_cast<int>(dip[3]);

        oss << ":" << dst_port;
        oss << " [" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "Other") << "]";

        return oss.str();
    }

    // Hash 函数（用于 unordered_map）
    size_t hash() const {
        // 简单的 hash 组合
        size_t h = 0;
        h ^= std::hash<uint32_t>{}(src_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint32_t>{}(dst_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(src_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t>{}(protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

} // namespace flow
} // namespace netguardian

// 为 FlowKey 提供 std::hash 特化（用于 unordered_map）
namespace std {
    template<>
    struct hash<netguardian::flow::FlowKey> {
        size_t operator()(const netguardian::flow::FlowKey& key) const {
            return key.hash();
        }
    };
}

#endif // NETGUARDIAN_FLOW_FLOW_KEY_H
