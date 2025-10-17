#ifndef NETGUARDIAN_DECODERS_IPV4_DECODER_H
#define NETGUARDIAN_DECODERS_IPV4_DECODER_H

#include "decoders/decoder_base.h"
#include <arpa/inet.h>
#include <sstream>
#include <vector>

namespace netguardian {
namespace decoders {

// IPv4 地址类型
struct IPv4Address {
    uint32_t addr;  // 网络字节序

    IPv4Address() : addr(0) {}
    explicit IPv4Address(uint32_t a) : addr(a) {}

    std::string to_string() const {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        return std::string(buf);
    }

    bool operator==(const IPv4Address& other) const {
        return addr == other.addr;
    }
};

// IPv4 解码数据
class IPv4Data : public DecodedData {
public:
    uint8_t version;
    uint8_t ihl;  // Internet Header Length (in 32-bit words)
    uint8_t tos;  // Type of Service
    uint16_t total_length;
    uint16_t identification;
    uint8_t flags;
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    IPv4Address src_ip;
    IPv4Address dst_ip;

    // 可选字段
    bool has_options;
    std::vector<uint8_t> options;

    IPv4Data()
        : version(0), ihl(0), tos(0), total_length(0)
        , identification(0), flags(0), fragment_offset(0)
        , ttl(0), protocol(0), checksum(0)
        , has_options(false)
    {}

    std::string to_string() const override {
        std::ostringstream oss;
        oss << "IPv4 [";
        oss << src_ip.to_string() << " -> " << dst_ip.to_string();
        oss << ", Proto: " << static_cast<int>(protocol);
        oss << ", TTL: " << static_cast<int>(ttl);
        oss << ", Len: " << total_length;
        if (is_fragmented()) {
            oss << ", Frag: offset=" << fragment_offset;
        }
        oss << "]";
        return oss.str();
    }

    bool has_field(const std::string& field_name) const override {
        return field_name == "src_ip" || field_name == "dst_ip" ||
               field_name == "protocol" || field_name == "ttl" ||
               field_name == "total_length";
    }

    std::any get_field(const std::string& field_name) const override {
        if (field_name == "src_ip") return src_ip.to_string();
        if (field_name == "dst_ip") return dst_ip.to_string();
        if (field_name == "protocol") return protocol;
        if (field_name == "ttl") return ttl;
        if (field_name == "total_length") return total_length;
        return std::any();
    }

    bool is_fragmented() const {
        return (flags & 0x01) || (fragment_offset > 0);
    }

    bool more_fragments() const {
        return (flags & 0x01) != 0;
    }

    bool dont_fragment() const {
        return (flags & 0x02) != 0;
    }

    uint16_t header_length() const {
        return ihl * 4;
    }
};

// IPv4 解码器
class IPv4Decoder : public DecoderBase {
public:
    std::shared_ptr<DecodedData> decode(const core::Packet& packet) override;
    std::string name() const override { return "IPv4"; }
    bool can_decode(const core::Packet& packet) const override;
};

} // namespace decoders
} // namespace netguardian

#endif // NETGUARDIAN_DECODERS_IPV4_DECODER_H
