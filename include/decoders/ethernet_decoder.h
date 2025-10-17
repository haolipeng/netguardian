#ifndef NETGUARDIAN_DECODERS_ETHERNET_DECODER_H
#define NETGUARDIAN_DECODERS_ETHERNET_DECODER_H

#include "decoders/decoder_base.h"
#include <array>
#include <sstream>
#include <iomanip>

namespace netguardian {
namespace decoders {

// MAC 地址类型
using MacAddress = std::array<uint8_t, 6>;

// Ethernet 解码数据
class EthernetData : public DecodedData {
public:
    MacAddress src_mac;
    MacAddress dst_mac;
    uint16_t ethertype;
    bool has_vlan;
    uint16_t vlan_id;
    uint16_t vlan_priority;

    EthernetData()
        : src_mac{0}
        , dst_mac{0}
        , ethertype(0)
        , has_vlan(false)
        , vlan_id(0)
        , vlan_priority(0)
    {}

    std::string to_string() const override {
        std::ostringstream oss;
        oss << "Ethernet [";
        oss << mac_to_string(src_mac) << " -> " << mac_to_string(dst_mac);
        oss << ", Type: 0x" << std::hex << std::setw(4) << std::setfill('0') << ethertype;
        if (has_vlan) {
            oss << ", VLAN: " << std::dec << vlan_id;
        }
        oss << "]";
        return oss.str();
    }

    bool has_field(const std::string& field_name) const override {
        return field_name == "src_mac" || field_name == "dst_mac" ||
               field_name == "ethertype" || field_name == "vlan_id";
    }

    std::any get_field(const std::string& field_name) const override {
        if (field_name == "src_mac") return src_mac;
        if (field_name == "dst_mac") return dst_mac;
        if (field_name == "ethertype") return ethertype;
        if (field_name == "vlan_id") return vlan_id;
        return std::any();
    }

    static std::string mac_to_string(const MacAddress& mac) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (size_t i = 0; i < mac.size(); ++i) {
            if (i > 0) oss << ":";
            oss << std::setw(2) << static_cast<int>(mac[i]);
        }
        return oss.str();
    }
};

// Ethernet 解码器
class EthernetDecoder : public DecoderBase {
public:
    std::shared_ptr<DecodedData> decode(const core::Packet& packet) override;
    std::string name() const override { return "Ethernet"; }
    bool can_decode(const core::Packet& packet) const override;

private:
    static constexpr uint16_t ETHERTYPE_VLAN = 0x8100;
};

} // namespace decoders
} // namespace netguardian

#endif // NETGUARDIAN_DECODERS_ETHERNET_DECODER_H
