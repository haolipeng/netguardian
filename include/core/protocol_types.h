#ifndef NETGUARDIAN_CORE_PROTOCOL_TYPES_H
#define NETGUARDIAN_CORE_PROTOCOL_TYPES_H

#include <cstdint>
#include <string>
#include <cstring>

namespace netguardian {
namespace core {

/**
 * Protocol types across all layers
 *
 * Values are chosen to match standard protocol numbers where applicable:
 * - Ethernet types (EtherType field)
 * - IP protocol numbers
 * - Well-known port numbers for L7
 */
enum class ProtocolType : uint16_t {
    UNKNOWN = 0,

    // Layer 2 - Data Link Layer
    ETHERNET = 0x0001,

    // Layer 3 - Network Layer (EtherType values)
    IPV4 = 0x0800,      // IPv4
    IPV6 = 0x86DD,      // IPv6
    ARP = 0x0806,       // ARP

    // Layer 4 - Transport Layer (use high values to avoid conflicts)
    ICMP = 0x1001,      // ICMP (not real value, internal use)
    IGMP = 0x1002,      // IGMP
    TCP = 0x1006,       // TCP
    UDP = 0x1011,       // UDP
    IPV6_ICMP = 0x103A, // ICMPv6
    SCTP = 0x1084,      // SCTP

    // Layer 7 - Application Layer (use high values)
    FTP = 0x2015,
    SSH = 0x2016,
    TELNET = 0x2017,
    SMTP = 0x2019,
    DNS = 0x2035,
    HTTP = 0x2050,
    POP3 = 0x206E,
    IMAP = 0x208F,
    HTTPS = 0x21BB,
    SMB = 0x21BD,
    MYSQL = 0x2CEA,
    RDP = 0x2D3D
};

/**
 * Network layer types
 */
enum class NetworkType : uint8_t {
    NONE = 0,
    IPV4 = 4,
    IPV6 = 6
};

/**
 * Transport layer types
 */
enum class TransportType : uint8_t {
    NONE = 0,
    TCP = 6,
    UDP = 17,
    ICMP = 1
};

// ============================================================================
// 分层协议信息结构
// ============================================================================

/**
 * Layer 2 (Data Link) 信息
 */
struct L2Info {
    ProtocolType type;          // 协议类型（ETHERNET等）
    uint16_t offset;            // 头部偏移量
    uint16_t length;            // 头部长度

    // 缓存的常用字段
    uint8_t src_mac[6];         // 源 MAC 地址
    uint8_t dst_mac[6];         // 目标 MAC 地址
    bool has_vlan;              // 是否有 VLAN 标签
    uint16_t vlan_id;           // VLAN ID

    L2Info()
        : type(ProtocolType::UNKNOWN)
        , offset(0)
        , length(0)
        , has_vlan(false)
        , vlan_id(0)
    {
        std::memset(src_mac, 0, 6);
        std::memset(dst_mac, 0, 6);
    }
};

/**
 * Layer 3 (Network) 信息
 */
struct L3Info {
    ProtocolType type;          // 协议类型（IPV4/IPV6）
    uint16_t offset;            // 头部偏移量
    uint16_t length;            // 头部长度

    // 缓存的常用字段（IPv4）
    uint32_t src_ip;            // 源 IP 地址（网络字节序）
    uint32_t dst_ip;            // 目标 IP 地址（网络字节序）
    uint8_t ttl;                // TTL
    uint8_t protocol;           // IP 协议号（用于 L4）
    uint16_t total_length;      // IP 总长度

    // IPv6 地址（如果需要）
    uint8_t src_ipv6[16];       // IPv6 源地址
    uint8_t dst_ipv6[16];       // IPv6 目标地址

    // 分片信息
    bool is_fragment;           // 是否为分片
    uint16_t fragment_offset;   // 分片偏移量
    uint16_t fragment_id;       // 分片 ID
    bool more_fragments;        // 是否有更多分片

    L3Info()
        : type(ProtocolType::UNKNOWN)
        , offset(0)
        , length(0)
        , src_ip(0)
        , dst_ip(0)
        , ttl(0)
        , protocol(0)
        , total_length(0)
        , is_fragment(false)
        , fragment_offset(0)
        , fragment_id(0)
        , more_fragments(false)
    {
        std::memset(src_ipv6, 0, 16);
        std::memset(dst_ipv6, 0, 16);
    }
};

/**
 * Layer 4 (Transport) 信息
 */
struct L4Info {
    ProtocolType type;          // 协议类型（TCP/UDP）
    uint16_t offset;            // 头部偏移量
    uint16_t length;            // 头部长度

    // 缓存的常用字段
    uint16_t src_port;          // 源端口
    uint16_t dst_port;          // 目标端口

    // TCP 特定字段
    uint32_t seq;               // 序列号
    uint32_t ack;               // 确认号
    uint8_t flags;              // TCP 标志位
    uint16_t window;            // 窗口大小

    // UDP 特定字段
    uint16_t udp_length;        // UDP 长度

    L4Info()
        : type(ProtocolType::UNKNOWN)
        , offset(0)
        , length(0)
        , src_port(0)
        , dst_port(0)
        , seq(0)
        , ack(0)
        , flags(0)
        , window(0)
        , udp_length(0)
    {}
};

/**
 * Layer 7 (Application) 信息
 */
struct L7Info {
    ProtocolType type;          // 协议类型（HTTP/DNS等）
    uint16_t offset;            // 应用层数据偏移量
    uint16_t length;            // 应用层数据长度

    L7Info()
        : type(ProtocolType::UNKNOWN)
        , offset(0)
        , length(0)
    {}
};

// ============================================================================
// 协议栈（分层设计 + 缓存常用字段）
// ============================================================================

/**
 * Protocol stack representing all layers of a packet
 *
 * 设计原则：
 * 1. 分层组织 - 每层信息独立，语义清晰
 * 2. 缓存字段 - 存储常用字段，避免重复解析
 * 3. 类型安全 - 使用结构体而非原始类型
 * 4. 易于扩展 - 添加新协议只需修改对应层
 */
struct ProtocolStack {
    // 各层信息
    L2Info l2;                  // 数据链路层
    L3Info l3;                  // 网络层
    L4Info l4;                  // 传输层
    L7Info l7;                  // 应用层

    // ========================================================================
    // 辅助方法 - 访问各层数据
    // ========================================================================

    /**
     * 获取各层头部指针（需要 Packet 对象）
     */
    template<typename PacketType>
    const uint8_t* l2_data(const PacketType& pkt) const {
        return pkt.data() + l2.offset;
    }

    template<typename PacketType>
    const uint8_t* l3_data(const PacketType& pkt) const {
        return pkt.data() + l3.offset;
    }

    template<typename PacketType>
    const uint8_t* l4_data(const PacketType& pkt) const {
        return pkt.data() + l4.offset;
    }

    template<typename PacketType>
    const uint8_t* l7_data(const PacketType& pkt) const {
        return pkt.data() + l7.offset;
    }

    // ========================================================================
    // 向后兼容接口（兼容旧代码）
    // ========================================================================

    // 协议类型（兼容旧代码）
    ProtocolType l2_type() const { return l2.type; }
    ProtocolType l3_type() const { return l3.type; }
    ProtocolType l4_type() const { return l4.type; }
    ProtocolType l7_type() const { return l7.type; }

    // 偏移量（兼容旧代码）
    uint16_t l2_offset() const { return l2.offset; }
    uint16_t l3_offset() const { return l3.offset; }
    uint16_t l4_offset() const { return l4.offset; }
    uint16_t l7_offset() const { return l7.offset; }

    // payload 兼容接口
    uint16_t payload_offset() const { return l7.offset; }
    uint16_t payload_len() const { return l7.length; }

    // VLAN 兼容接口
    bool has_vlan() const { return l2.has_vlan; }
    uint16_t vlan_id() const { return l2.vlan_id; }

    // 重置
    void reset() {
        l2 = L2Info();
        l3 = L3Info();
        l4 = L4Info();
        l7 = L7Info();
    }
};

/**
 * Common Ethernet types
 */
namespace EtherType {
    constexpr uint16_t IPV4 = 0x0800;
    constexpr uint16_t ARP = 0x0806;
    constexpr uint16_t VLAN = 0x8100;
    constexpr uint16_t IPV6 = 0x86DD;
    constexpr uint16_t MPLS_UNICAST = 0x8847;
    constexpr uint16_t MPLS_MULTICAST = 0x8848;
}

/**
 * IP protocol numbers
 */
namespace IPProto {
    constexpr uint8_t ICMP = 1;
    constexpr uint8_t IGMP = 2;
    constexpr uint8_t TCP = 6;
    constexpr uint8_t UDP = 17;
    constexpr uint8_t IPV6 = 41;
    constexpr uint8_t IPV6_ROUTE = 43;
    constexpr uint8_t IPV6_FRAG = 44;
    constexpr uint8_t GRE = 47;
    constexpr uint8_t ESP = 50;
    constexpr uint8_t AH = 51;
    constexpr uint8_t IPV6_ICMP = 58;
    constexpr uint8_t IPV6_NONXT = 59;
    constexpr uint8_t IPV6_OPTS = 60;
    constexpr uint8_t SCTP = 132;
}

/**
 * Well-known ports
 */
namespace WellKnownPort {
    constexpr uint16_t FTP = 21;
    constexpr uint16_t SSH = 22;
    constexpr uint16_t TELNET = 23;
    constexpr uint16_t SMTP = 25;
    constexpr uint16_t DNS = 53;
    constexpr uint16_t HTTP = 80;
    constexpr uint16_t POP3 = 110;
    constexpr uint16_t IMAP = 143;
    constexpr uint16_t HTTPS = 443;
    constexpr uint16_t SMB = 445;
    constexpr uint16_t MYSQL = 3306;
    constexpr uint16_t RDP = 3389;
}

/**
 * Convert protocol type to string
 */
const char* protocol_type_to_string(ProtocolType type);

/**
 * Get protocol name for L7 based on port
 */
const char* port_to_protocol_name(uint16_t port);

} // namespace core
} // namespace netguardian

#endif // NETGUARDIAN_CORE_PROTOCOL_TYPES_H
