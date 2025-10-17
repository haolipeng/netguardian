#include "decoders/ethernet_decoder.h"
#include "decoders/protocol_headers.h"
#include "core/protocol_types.h"
#include <arpa/inet.h>
#include <cstring>

namespace netguardian {
namespace decoders {

bool EthernetDecoder::can_decode(const core::Packet& packet) const {
    // 检查是否是 Ethernet 帧
    return packet.protocol_stack().l2_type == core::ProtocolType::ETHERNET;
}

std::shared_ptr<DecodedData> EthernetDecoder::decode(const core::Packet& packet) {
    if (!can_decode(packet)) {
        return nullptr;
    }

    const auto& stack = packet.protocol_stack();
    if (static_cast<size_t>(stack.l2_offset) + sizeof(EthernetHeader) > packet.length()) {
        return nullptr;  // 数据不足
    }

    auto eth_data = std::make_shared<EthernetData>();

    // 使用结构体指针方式访问数据
    const EthernetHeader* hdr = reinterpret_cast<const EthernetHeader*>(
        packet.data() + stack.l2_offset
    );

    // 使用结构体字段直接访问
    std::memcpy(eth_data->dst_mac.data(), hdr->dst_mac, 6);
    std::memcpy(eth_data->src_mac.data(), hdr->src_mac, 6);

    uint16_t ethertype = ntohs(hdr->ether_type);

    // 检查是否有 VLAN 标签
    if (ethertype == ETHERTYPE_VLAN) {
        eth_data->has_vlan = true;

        // 检查 VLAN 头部是否完整
        if (static_cast<size_t>(stack.l2_offset) + sizeof(EthernetHeader) + sizeof(VlanHeader) > packet.length()) {
            return nullptr;
        }

        // 使用 VLAN 结构体
        const VlanHeader* vlan_hdr = reinterpret_cast<const VlanHeader*>(hdr + 1);
        eth_data->vlan_id = vlan_id(vlan_hdr);
        eth_data->vlan_priority = vlan_priority(vlan_hdr);

        // 真实的 EtherType 在 VLAN 标签之后
        ethertype = ntohs(vlan_hdr->ether_type);
    }

    eth_data->ethertype = ethertype;

    return eth_data;
}

} // namespace decoders
} // namespace netguardian
