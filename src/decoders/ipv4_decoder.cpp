#include "decoders/ipv4_decoder.h"
#include "decoders/protocol_headers.h"
#include "core/protocol_types.h"
#include <arpa/inet.h>
#include <cstring>

namespace netguardian {
namespace decoders {

bool IPv4Decoder::can_decode(const core::Packet& packet) const {
    return packet.protocol_stack().l3_type == core::ProtocolType::IPV4;
}

std::shared_ptr<DecodedData> IPv4Decoder::decode(const core::Packet& packet) {
    if (!can_decode(packet)) {
        return nullptr;
    }

    const auto& stack = packet.protocol_stack();
    if (static_cast<size_t>(stack.l3_offset) + sizeof(IPv4Header) > packet.length()) {
        return nullptr;  // 最小 IPv4 头部是 20 字节
    }

    auto ipv4_data = std::make_shared<IPv4Data>();

    // 使用结构体指针方式访问数据
    const IPv4Header* hdr = reinterpret_cast<const IPv4Header*>(
        packet.data() + stack.l3_offset
    );

    // 版本和头部长度
    ipv4_data->version = ipv4_version(hdr);
    ipv4_data->ihl = hdr->version_ihl & 0x0F;

    // 检查版本
    if (ipv4_data->version != 4) {
        return nullptr;
    }

    // 检查头部长度
    uint16_t header_len = ipv4_header_length(hdr);
    if (header_len < 20 || static_cast<size_t>(stack.l3_offset) + header_len > packet.length()) {
        return nullptr;
    }

    // 使用结构体字段直接访问（更清晰）
    ipv4_data->tos = hdr->tos;
    ipv4_data->total_length = ntohs(hdr->total_length);
    ipv4_data->identification = ntohs(hdr->identification);
    ipv4_data->flags = ipv4_flags(hdr);
    ipv4_data->fragment_offset = ipv4_fragment_offset(hdr);
    ipv4_data->ttl = hdr->ttl;
    ipv4_data->protocol = hdr->protocol;
    ipv4_data->checksum = ntohs(hdr->checksum);

    // IP 地址（已经是网络字节序）
    ipv4_data->src_ip = IPv4Address(hdr->src_ip);
    ipv4_data->dst_ip = IPv4Address(hdr->dst_ip);

    // 选项（如果有）
    if (header_len > 20) {
        ipv4_data->has_options = true;
        size_t options_len = header_len - 20;
        ipv4_data->options.resize(options_len);

        const uint8_t* options_ptr = reinterpret_cast<const uint8_t*>(hdr + 1);
        std::memcpy(ipv4_data->options.data(), options_ptr, options_len);
    }

    return ipv4_data;
}

} // namespace decoders
} // namespace netguardian
