#ifndef NETGUARDIAN_DECODERS_PROTOCOL_HEADERS_H
#define NETGUARDIAN_DECODERS_PROTOCOL_HEADERS_H

#include <cstdint>
#include <arpa/inet.h>

namespace netguardian {
namespace decoders {

// 所有协议头部结构体使用网络字节序（大端）
// 使用 __attribute__((packed)) 确保没有填充字节

//=============================================================================
// L2: 数据链路层
//=============================================================================

// Ethernet II 头部
struct EthernetHeader {
    uint8_t  dst_mac[6];      // 目标 MAC 地址
    uint8_t  src_mac[6];      // 源 MAC 地址
    uint16_t ether_type;      // 以太网类型
} __attribute__((packed));

// VLAN 标签 (802.1Q)
struct VlanHeader {
    uint16_t tci;             // Tag Control Information (优先级 + CFI + VLAN ID)
    uint16_t ether_type;      // 封装的以太网类型
} __attribute__((packed));

//=============================================================================
// L3: 网络层
//=============================================================================

// IPv4 头部
struct IPv4Header {
    uint8_t  version_ihl;     // 版本 (4 bits) + 头部长度 (4 bits)
    uint8_t  tos;             // 服务类型
    uint16_t total_length;    // 总长度
    uint16_t identification;  // 标识
    uint16_t flags_offset;    // 标志 (3 bits) + 片偏移 (13 bits)
    uint8_t  ttl;             // 生存时间
    uint8_t  protocol;        // 协议
    uint16_t checksum;        // 头部校验和
    uint32_t src_ip;          // 源 IP 地址
    uint32_t dst_ip;          // 目标 IP 地址
    // 可选字段和数据紧随其后
} __attribute__((packed));

// IPv6 头部
struct IPv6Header {
    uint32_t version_class_label;  // 版本(4) + 流量类(8) + 流标签(20)
    uint16_t payload_length;       // 负载长度
    uint8_t  next_header;          // 下一个头部
    uint8_t  hop_limit;            // 跳数限制
    uint8_t  src_ip[16];           // 源 IP 地址
    uint8_t  dst_ip[16];           // 目标 IP 地址
} __attribute__((packed));

// ICMP 头部
struct IcmpHeader {
    uint8_t  type;            // ICMP 类型
    uint8_t  code;            // ICMP 代码
    uint16_t checksum;        // 校验和
    union {
        struct {
            uint16_t id;      // 标识符
            uint16_t seq;     // 序列号
        } echo;
        uint32_t gateway;     // 网关地址
        struct {
            uint16_t unused;
            uint16_t mtu;     // MTU
        } frag;
    } un;
} __attribute__((packed));

//=============================================================================
// L4: 传输层
//=============================================================================

// TCP 头部
struct TcpHeader {
    uint16_t src_port;        // 源端口
    uint16_t dst_port;        // 目标端口
    uint32_t seq_num;         // 序列号
    uint32_t ack_num;         // 确认号
    uint8_t  data_offset;     // 数据偏移 (4 bits) + 保留 (4 bits)
    uint8_t  flags;           // TCP 标志
    uint16_t window_size;     // 窗口大小
    uint16_t checksum;        // 校验和
    uint16_t urgent_pointer;  // 紧急指针
    // 可选字段和数据紧随其后
} __attribute__((packed));

// TCP 标志位定义
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20
#define TCP_FLAG_ECE  0x40
#define TCP_FLAG_CWR  0x80

// UDP 头部
struct UdpHeader {
    uint16_t src_port;        // 源端口
    uint16_t dst_port;        // 目标端口
    uint16_t length;          // 长度
    uint16_t checksum;        // 校验和
} __attribute__((packed));

//=============================================================================
// L7: 应用层
//=============================================================================

// DNS 头部
struct DnsHeader {
    uint16_t transaction_id;  // 事务 ID
    uint16_t flags;           // 标志
    uint16_t questions;       // 问题数
    uint16_t answers;         // 答复数
    uint16_t authority;       // 授权记录数
    uint16_t additional;      // 附加记录数
} __attribute__((packed));

// DNS 标志位定义
#define DNS_FLAG_QR     0x8000  // Query/Response
#define DNS_FLAG_AA     0x0400  // Authoritative Answer
#define DNS_FLAG_TC     0x0200  // Truncated
#define DNS_FLAG_RD     0x0100  // Recursion Desired
#define DNS_FLAG_RA     0x0080  // Recursion Available

//=============================================================================
// 辅助宏和内联函数
//=============================================================================

// IPv4 头部长度获取（单位：字节）
static inline uint8_t ipv4_header_length(const IPv4Header* hdr) {
    return (hdr->version_ihl & 0x0F) * 4;
}

// IPv4 版本获取
static inline uint8_t ipv4_version(const IPv4Header* hdr) {
    return (hdr->version_ihl >> 4) & 0x0F;
}

// IPv4 标志位获取
static inline uint8_t ipv4_flags(const IPv4Header* hdr) {
    return (ntohs(hdr->flags_offset) >> 13) & 0x07;
}

// IPv4 片偏移获取
static inline uint16_t ipv4_fragment_offset(const IPv4Header* hdr) {
    return ntohs(hdr->flags_offset) & 0x1FFF;
}

// TCP 头部长度获取（单位：字节）
static inline uint8_t tcp_header_length(const TcpHeader* hdr) {
    return (hdr->data_offset >> 4) * 4;
}

// TCP 标志位检查
static inline bool tcp_has_flag(const TcpHeader* hdr, uint8_t flag) {
    return (hdr->flags & flag) != 0;
}

// VLAN ID 获取
static inline uint16_t vlan_id(const VlanHeader* hdr) {
    return ntohs(hdr->tci) & 0x0FFF;
}

// VLAN 优先级获取
static inline uint8_t vlan_priority(const VlanHeader* hdr) {
    return (ntohs(hdr->tci) >> 13) & 0x07;
}

} // namespace decoders
} // namespace netguardian

#endif // NETGUARDIAN_DECODERS_PROTOCOL_HEADERS_H
