#include "decoders/tcp_decoder.h"
#include "decoders/protocol_headers.h"
#include "core/protocol_types.h"
#include <arpa/inet.h>
#include <cstring>

namespace netguardian {
namespace decoders {

bool TcpDecoder::can_decode(const core::Packet& packet) const {
    return packet.protocol_stack().l4_type == core::ProtocolType::TCP;
}

std::shared_ptr<DecodedData> TcpDecoder::decode(const core::Packet& packet) {
    if (!can_decode(packet)) {
        return nullptr;
    }

    const auto& stack = packet.protocol_stack();
    if (static_cast<size_t>(stack.l4_offset) + sizeof(TcpHeader) > packet.length()) {
        return nullptr;  // 最小 TCP 头部是 20 字节
    }

    auto tcp_data = std::make_shared<TcpData>();

    // 使用结构体指针方式访问数据
    const TcpHeader* hdr = reinterpret_cast<const TcpHeader*>(
        packet.data() + stack.l4_offset
    );

    // 使用结构体字段直接访问
    tcp_data->src_port = ntohs(hdr->src_port);
    tcp_data->dst_port = ntohs(hdr->dst_port);
    tcp_data->seq_num = ntohl(hdr->seq_num);
    tcp_data->ack_num = ntohl(hdr->ack_num);
    tcp_data->data_offset = (hdr->data_offset >> 4) & 0x0F;
    tcp_data->window_size = ntohs(hdr->window_size);
    tcp_data->checksum = ntohs(hdr->checksum);
    tcp_data->urgent_pointer = ntohs(hdr->urgent_pointer);

    // 使用宏定义解析标志位（更清晰）
    tcp_data->flags.fin = tcp_has_flag(hdr, TCP_FLAG_FIN);
    tcp_data->flags.syn = tcp_has_flag(hdr, TCP_FLAG_SYN);
    tcp_data->flags.rst = tcp_has_flag(hdr, TCP_FLAG_RST);
    tcp_data->flags.psh = tcp_has_flag(hdr, TCP_FLAG_PSH);
    tcp_data->flags.ack = tcp_has_flag(hdr, TCP_FLAG_ACK);
    tcp_data->flags.urg = tcp_has_flag(hdr, TCP_FLAG_URG);
    tcp_data->flags.ece = tcp_has_flag(hdr, TCP_FLAG_ECE);
    tcp_data->flags.cwr = tcp_has_flag(hdr, TCP_FLAG_CWR);

    // 检查头部长度
    uint16_t header_len = tcp_header_length(hdr);
    if (header_len < 20 || static_cast<size_t>(stack.l4_offset) + header_len > packet.length()) {
        return nullptr;
    }

    // 选项（如果有）
    if (header_len > 20) {
        tcp_data->has_options = true;
        size_t options_len = header_len - 20;
        tcp_data->options.resize(options_len);

        const uint8_t* options_ptr = reinterpret_cast<const uint8_t*>(hdr + 1);
        std::memcpy(tcp_data->options.data(), options_ptr, options_len);
    }

    return tcp_data;
}

} // namespace decoders
} // namespace netguardian
