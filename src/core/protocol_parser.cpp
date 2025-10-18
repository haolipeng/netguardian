#include "core/protocol_parser.h"
#include <pcap/dlt.h>
#include <arpa/inet.h>
#include <cstring>

namespace netguardian {
namespace core {

bool ProtocolParser::parse(Packet& packet, int datalink_type) {
    if (!packet.data() || packet.length() == 0) {
        return false;
    }

    ProtocolStack& stack = packet.protocol_stack();
    const uint8_t* data = packet.data();
    size_t len = packet.length();

    // Parse L2
    if (datalink_type == DLT_EN10MB) {
        if (!parse_ethernet(data, len, stack)) {
            return false;
        }
    } else {
        // Unsupported datalink type
        return false;
    }

    // Parse L3
    if (stack.l3_offset < len) {
        uint16_t ethertype = ntohs(*reinterpret_cast<const uint16_t*>(data + 12));
        
        // Handle VLAN
        if (ethertype == 0x8100) {
            stack.has_vlan = true;
            stack.vlan_id = ntohs(*reinterpret_cast<const uint16_t*>(data + 14)) & 0x0FFF;
            ethertype = ntohs(*reinterpret_cast<const uint16_t*>(data + 16));
            stack.l3_offset += 4;
        }

        const uint8_t* l3_data = data + stack.l3_offset;
        size_t l3_len = len - stack.l3_offset;

        if (ethertype == 0x0800) {  // IPv4
            parse_ipv4(l3_data, l3_len, stack);
        } else if (ethertype == 0x86DD) {  // IPv6
            parse_ipv6(l3_data, l3_len, stack);
        } else if (ethertype == 0x0806) {  // ARP
            stack.l3_type = ProtocolType::ARP;
            stack.l3_len = 28;
        }
    }

    // Parse L4
    if (stack.l4_offset > 0 && stack.l4_offset < len) {
        const uint8_t* l4_data = data + stack.l4_offset;
        size_t l4_len = len - stack.l4_offset;

        if (stack.l3_type == ProtocolType::IPV4 || stack.l3_type == ProtocolType::IPV6) {
            uint8_t protocol = *(data + stack.l3_offset + (stack.l3_type == ProtocolType::IPV4 ? 9 : 6));
            
            if (protocol == 6) {  // TCP
                parse_tcp(l4_data, l4_len, stack);
            } else if (protocol == 17) {  // UDP
                parse_udp(l4_data, l4_len, stack);
            } else if (protocol == 1) {  // ICMP
                stack.l4_type = ProtocolType::ICMP;
                stack.l4_len = 8;
                stack.payload_offset = stack.l4_offset + 8;
            }
        }
    }

    packet.set_decoded(true);
    return true;
}

bool ProtocolParser::parse_ethernet(const uint8_t* data, size_t len, ProtocolStack& stack) {
    if (len < 14) {
        return false;
    }

    stack.l2_type = ProtocolType::ETHERNET;
    stack.l2_offset = 0;
    stack.l2_len = 14;
    stack.l3_offset = 14;

    return true;
}

bool ProtocolParser::parse_ipv4(const uint8_t* data, size_t len, ProtocolStack& stack) {
    if (len < 20) {
        return false;
    }

    stack.l3_type = ProtocolType::IPV4;
    stack.l3_len = (data[0] & 0x0F) * 4;  // IHL field
    stack.l4_offset = stack.l3_offset + stack.l3_len;

    return true;
}

bool ProtocolParser::parse_ipv6(const uint8_t* data, size_t len, ProtocolStack& stack) {
    if (len < 40) {
        return false;
    }

    stack.l3_type = ProtocolType::IPV6;
    stack.l3_len = 40;  // Fixed IPv6 header
    stack.l4_offset = stack.l3_offset + 40;

    return true;
}

bool ProtocolParser::parse_tcp(const uint8_t* data, size_t len, ProtocolStack& stack) {
    if (len < 20) {
        return false;
    }

    stack.l4_type = ProtocolType::TCP;
    stack.l4_len = ((data[12] >> 4) & 0x0F) * 4;  // Data offset field
    stack.payload_offset = stack.l4_offset + stack.l4_len;
    stack.payload_len = len - stack.l4_len;

    return true;
}

bool ProtocolParser::parse_udp(const uint8_t* data, size_t len, ProtocolStack& stack) {
    if (len < 8) {
        return false;
    }

    stack.l4_type = ProtocolType::UDP;
    stack.l4_len = 8;  // Fixed UDP header
    stack.payload_offset = stack.l4_offset + 8;
    stack.payload_len = len - 8;

    return true;
}

} // namespace core
} // namespace netguardian
