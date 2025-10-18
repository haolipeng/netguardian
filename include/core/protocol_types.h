#ifndef NETGUARDIAN_CORE_PROTOCOL_TYPES_H
#define NETGUARDIAN_CORE_PROTOCOL_TYPES_H

#include <cstdint>
#include <string>

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

/**
 * Protocol stack representing all layers of a packet
 */
struct ProtocolStack {
    // Protocol types at each layer
    ProtocolType l2_type;           // Data Link (usually Ethernet)
    ProtocolType l3_type;           // Network (IP/ARP)
    ProtocolType l4_type;           // Transport (TCP/UDP/ICMP)
    ProtocolType l7_type;           // Application (HTTP/DNS/etc)

    // Offsets to each layer header (from start of packet)
    uint16_t l2_offset;
    uint16_t l3_offset;
    uint16_t l4_offset;
    uint16_t l7_offset;

    // Header lengths
    uint16_t l2_len;
    uint16_t l3_len;
    uint16_t l4_len;

    // Payload offset and length
    uint16_t payload_offset;
    uint16_t payload_len;

    // Convenience flags
    bool has_vlan;
    uint16_t vlan_id;

    ProtocolStack()
        : l2_type(ProtocolType::UNKNOWN)
        , l3_type(ProtocolType::UNKNOWN)
        , l4_type(ProtocolType::UNKNOWN)
        , l7_type(ProtocolType::UNKNOWN)
        , l2_offset(0)
        , l3_offset(0)
        , l4_offset(0)
        , l7_offset(0)
        , l2_len(0)
        , l3_len(0)
        , l4_len(0)
        , payload_offset(0)
        , payload_len(0)
        , has_vlan(false)
        , vlan_id(0)
    {}
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
