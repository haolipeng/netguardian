#include "decoders/udp_decoder.h"
#include "decoders/protocol_headers.h"
#include "core/protocol_types.h"
#include <arpa/inet.h>

namespace netguardian {
namespace decoders {

bool UdpDecoder::can_decode(const core::Packet& packet) const {
    return packet.protocol_stack().l4_type == core::ProtocolType::UDP;
}

std::shared_ptr<DecodedData> UdpDecoder::decode(const core::Packet& packet) {
    if (!can_decode(packet)) {
        return nullptr;
    }

    const auto& stack = packet.protocol_stack();
    if (static_cast<size_t>(stack.l4_offset) + sizeof(UdpHeader) > packet.length()) {
        return nullptr;  // UDP 头部是 8 字节
    }

    auto udp_data = std::make_shared<UdpData>();

    // 使用结构体指针方式访问数据
    const UdpHeader* hdr = reinterpret_cast<const UdpHeader*>(
        packet.data() + stack.l4_offset
    );

    // 使用结构体字段直接访问
    udp_data->src_port = ntohs(hdr->src_port);
    udp_data->dst_port = ntohs(hdr->dst_port);
    udp_data->length = ntohs(hdr->length);
    udp_data->checksum = ntohs(hdr->checksum);

    return udp_data;
}

} // namespace decoders
} // namespace netguardian
