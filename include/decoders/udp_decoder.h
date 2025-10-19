#ifndef NETGUARDIAN_DECODERS_UDP_DECODER_H
#define NETGUARDIAN_DECODERS_UDP_DECODER_H

#include "decoders/decoder_base.h"
#include <sstream>

namespace netguardian {
namespace decoders {

// UDP 解码数据
class UdpData : public DecodedData {
public:
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;

    UdpData()
        : src_port(0), dst_port(0), length(0), checksum(0)
    {}

    std::string to_string() const override {
        std::ostringstream oss;
        oss << "UDP [";
        oss << src_port << " -> " << dst_port;
        oss << ", Len: " << length;
        oss << "]";
        return oss.str();
    }

    bool has_field(const std::string& field_name) const override {
        return field_name == "src_port" || field_name == "dst_port" ||
               field_name == "length";
    }

    utils::any get_field(const std::string& field_name) const override {
        if (field_name == "src_port") return src_port;
        if (field_name == "dst_port") return dst_port;
        if (field_name == "length") return length;
        return utils::any();
    }
};

// UDP 解码器
class UdpDecoder : public DecoderBase {
public:
    std::shared_ptr<DecodedData> decode(const core::Packet& packet) override;
    std::string name() const override { return "UDP"; }
    bool can_decode(const core::Packet& packet) const override;
};

} // namespace decoders
} // namespace netguardian

#endif // NETGUARDIAN_DECODERS_UDP_DECODER_H
