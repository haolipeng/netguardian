#ifndef NETGUARDIAN_DECODERS_PACKET_INFO_H
#define NETGUARDIAN_DECODERS_PACKET_INFO_H

#include <cstdint>
#include <cstring>

namespace netguardian {
namespace decoders {

// 简化的数据包信息结构
// 用于告警生成，包含数据包的关键字段
struct PacketInfo {
    // 基本信息
    uint32_t packet_length;

    // 链路层
    bool has_ethernet;

    // 网络层
    bool has_ipv4;
    bool has_ipv6;
    uint32_t ipv4_src;          // 网络字节序
    uint32_t ipv4_dst;          // 网络字节序
    uint8_t ipv4_ttl;
    uint8_t ipv4_protocol;

    // 传输层
    bool has_tcp;
    bool has_udp;
    bool has_icmp;

    uint16_t tcp_src_port;
    uint16_t tcp_dst_port;
    bool tcp_flags_syn;
    bool tcp_flags_ack;
    bool tcp_flags_fin;
    bool tcp_flags_rst;
    bool tcp_flags_psh;
    bool tcp_flags_urg;

    uint16_t udp_src_port;
    uint16_t udp_dst_port;

    // 构造函数
    PacketInfo()
        : packet_length(0)
        , has_ethernet(false)
        , has_ipv4(false)
        , has_ipv6(false)
        , ipv4_src(0)
        , ipv4_dst(0)
        , ipv4_ttl(0)
        , ipv4_protocol(0)
        , has_tcp(false)
        , has_udp(false)
        , has_icmp(false)
        , tcp_src_port(0)
        , tcp_dst_port(0)
        , tcp_flags_syn(false)
        , tcp_flags_ack(false)
        , tcp_flags_fin(false)
        , tcp_flags_rst(false)
        , tcp_flags_psh(false)
        , tcp_flags_urg(false)
        , udp_src_port(0)
        , udp_dst_port(0)
    {}
};

} // namespace decoders
} // namespace netguardian

#endif // NETGUARDIAN_DECODERS_PACKET_INFO_H
