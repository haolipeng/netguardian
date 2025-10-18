#ifndef NETGUARDIAN_CORE_PACKET_H
#define NETGUARDIAN_CORE_PACKET_H

#include "core/protocol_types.h"
#include <cstdint>
#include <memory>
#include <chrono>

namespace netguardian {
namespace core {

/**
 * Packet structure representing a captured network packet
 */
class Packet {
public:
    using TimePoint = std::chrono::system_clock::time_point;

    Packet();
    ~Packet();

    // Copy constructor and assignment (rule of three)
    Packet(const Packet& other);
    Packet& operator=(const Packet& other);

    // Packet data access
    const uint8_t* data() const { return data_; }
    uint8_t* data() { return data_; }
    size_t length() const { return length_; }
    size_t caplen() const { return caplen_; }

    // Timestamp
    TimePoint timestamp() const { return timestamp_; }
    void set_timestamp(TimePoint ts) { timestamp_ = ts; }

    // Packet metadata
    uint32_t interface_id() const { return interface_id_; }
    void set_interface_id(uint32_t id) { interface_id_ = id; }

    // Packet layers
    bool is_decoded() const { return decoded_; }
    void set_decoded(bool decoded) { decoded_ = decoded; }

    // Protocol stack access
    const ProtocolStack& protocol_stack() const { return protocol_stack_; }
    ProtocolStack& protocol_stack() { return protocol_stack_; }

    // Convenience protocol checks
    bool is_ethernet() const { return protocol_stack_.l2_type == ProtocolType::ETHERNET; }
    bool is_ipv4() const { return protocol_stack_.l3_type == ProtocolType::IPV4; }
    bool is_ipv6() const { return protocol_stack_.l3_type == ProtocolType::IPV6; }
    bool is_arp() const { return protocol_stack_.l3_type == ProtocolType::ARP; }
    bool is_tcp() const { return protocol_stack_.l4_type == ProtocolType::TCP; }
    bool is_udp() const { return protocol_stack_.l4_type == ProtocolType::UDP; }
    bool is_icmp() const { return protocol_stack_.l4_type == ProtocolType::ICMP; }

    // Layer offsets (deprecated - use protocol_stack() instead)
    uint16_t eth_offset() const { return protocol_stack_.l2_offset; }
    uint16_t ip_offset() const { return protocol_stack_.l3_offset; }
    uint16_t transport_offset() const { return protocol_stack_.l4_offset; }
    uint16_t payload_offset() const { return protocol_stack_.payload_offset; }

    void set_eth_offset(uint16_t offset) { protocol_stack_.l2_offset = offset; }
    void set_ip_offset(uint16_t offset) { protocol_stack_.l3_offset = offset; }
    void set_transport_offset(uint16_t offset) { protocol_stack_.l4_offset = offset; }
    void set_payload_offset(uint16_t offset) { protocol_stack_.payload_offset = offset; }

    // Utility methods
    void reset();
    bool allocate(size_t size);

private:
    uint8_t* data_;
    size_t length_;
    size_t caplen_;
    TimePoint timestamp_;
    uint32_t interface_id_;
    bool decoded_;

    // Protocol stack information
    ProtocolStack protocol_stack_;

    // Deprecated - kept for compatibility (removed later)
    uint16_t eth_offset_;
    uint16_t ip_offset_;
    uint16_t transport_offset_;
    uint16_t payload_offset_;
};

using PacketPtr = std::shared_ptr<Packet>;

} // namespace core
} // namespace netguardian

#endif // NETGUARDIAN_CORE_PACKET_H
