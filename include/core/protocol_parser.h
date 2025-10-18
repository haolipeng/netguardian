#ifndef NETGUARDIAN_CORE_PROTOCOL_PARSER_H
#define NETGUARDIAN_CORE_PROTOCOL_PARSER_H

#include "core/packet.h"
#include "core/protocol_types.h"

namespace netguardian {
namespace core {

/**
 * Protocol Parser - Fast parsing of L2/L3/L4 headers
 * 
 * This is a lightweight, performance-optimized parser that extracts
 * basic protocol information from packet headers without deep inspection.
 */
class ProtocolParser {
public:
    /**
     * Parse packet headers (L2-L4)
     * @param packet Packet to parse
     * @param datalink_type Datalink type from pcap (DLT_*)
     * @return true if parsing succeeded
     */
    static bool parse(Packet& packet, int datalink_type);

private:
    static bool parse_ethernet(const uint8_t* data, size_t len, ProtocolStack& stack);
    static bool parse_ipv4(const uint8_t* data, size_t len, ProtocolStack& stack);
    static bool parse_ipv6(const uint8_t* data, size_t len, ProtocolStack& stack);
    static bool parse_tcp(const uint8_t* data, size_t len, ProtocolStack& stack);
    static bool parse_udp(const uint8_t* data, size_t len, ProtocolStack& stack);
};

} // namespace core
} // namespace netguardian

#endif // NETGUARDIAN_CORE_PROTOCOL_PARSER_H
