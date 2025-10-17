#include "decoders/dns_decoder.h"
#include "core/protocol_types.h"
#include <arpa/inet.h>
#include <cstring>

namespace netguardian {
namespace decoders {

bool DnsDecoder::can_decode(const core::Packet& packet) const {
    // DNS 通常使用 UDP 端口 53
    const auto& stack = packet.protocol_stack();
    if (stack.l4_type != core::ProtocolType::UDP) {
        return false;
    }

    // 需要有应用层数据，且至少 12 字节（DNS 头部大小）
    return stack.payload_len >= 12;
}

std::shared_ptr<DecodedData> DnsDecoder::decode(const core::Packet& packet) {
    if (!can_decode(packet)) {
        return nullptr;
    }

    const auto& stack = packet.protocol_stack();
    const uint8_t* data = packet.data() + stack.payload_offset;
    size_t len = stack.payload_len;

    auto dns_data = std::make_shared<DnsData>();

    // 解析 DNS 头部（12 字节）
    dns_data->transaction_id = ntohs(*reinterpret_cast<const uint16_t*>(data));

    uint16_t flags = ntohs(*reinterpret_cast<const uint16_t*>(data + 2));
    dns_data->is_query = ((flags & 0x8000) == 0);
    dns_data->opcode = (flags >> 11) & 0x0F;
    dns_data->authoritative = (flags & 0x0400) != 0;
    dns_data->truncated = (flags & 0x0200) != 0;
    dns_data->recursion_desired = (flags & 0x0100) != 0;
    dns_data->recursion_available = (flags & 0x0080) != 0;
    dns_data->response_code = flags & 0x000F;

    dns_data->question_count = ntohs(*reinterpret_cast<const uint16_t*>(data + 4));
    dns_data->answer_count = ntohs(*reinterpret_cast<const uint16_t*>(data + 6));
    dns_data->authority_count = ntohs(*reinterpret_cast<const uint16_t*>(data + 8));
    dns_data->additional_count = ntohs(*reinterpret_cast<const uint16_t*>(data + 10));

    size_t offset = 12;

    // 解析查询部分
    for (int i = 0; i < dns_data->question_count && offset < len; ++i) {
        DnsQuery query;

        // 解析域名
        query.qname = parse_domain_name(data, len, offset, data);
        if (offset + 4 > len) break;

        // 查询类型和类
        query.qtype = ntohs(*reinterpret_cast<const uint16_t*>(data + offset));
        offset += 2;
        query.qclass = ntohs(*reinterpret_cast<const uint16_t*>(data + offset));
        offset += 2;

        dns_data->queries.push_back(query);
    }

    // 简化实现：只解析答复部分的域名（不解析 RDATA）
    for (int i = 0; i < dns_data->answer_count && offset < len; ++i) {
        DnsResourceRecord rr;

        // 解析域名
        rr.name = parse_domain_name(data, len, offset, data);
        if (offset + 10 > len) break;

        // 类型、类、TTL、数据长度
        rr.type = ntohs(*reinterpret_cast<const uint16_t*>(data + offset));
        offset += 2;
        rr.rclass = ntohs(*reinterpret_cast<const uint16_t*>(data + offset));
        offset += 2;
        rr.ttl = ntohl(*reinterpret_cast<const uint32_t*>(data + offset));
        offset += 4;

        uint16_t rdlength = ntohs(*reinterpret_cast<const uint16_t*>(data + offset));
        offset += 2;

        // 读取 RDATA
        if (offset + rdlength <= len) {
            rr.rdata.resize(rdlength);
            std::memcpy(rr.rdata.data(), data + offset, rdlength);
            offset += rdlength;
        }

        dns_data->answers.push_back(rr);
    }

    return dns_data;
}

std::string DnsDecoder::parse_domain_name(const uint8_t* data, size_t len,
                                          size_t& offset, const uint8_t* msg_start) {
    std::string domain;
    bool jumped = false;
    size_t orig_offset = offset;
    size_t max_jumps = 10;  // 防止无限循环

    while (offset < len && max_jumps > 0) {
        uint8_t label_len = data[offset];

        // 检查是否是指针（压缩）
        if ((label_len & 0xC0) == 0xC0) {
            if (offset + 1 >= len) break;

            // 指针：12位偏移量
            uint16_t pointer = ((label_len & 0x3F) << 8) | data[offset + 1];
            if (!jumped) {
                orig_offset = offset + 2;
                jumped = true;
            }
            offset = pointer;
            max_jumps--;
            continue;
        }

        // 标签结束
        if (label_len == 0) {
            offset++;
            break;
        }

        // 检查标签长度
        if (offset + 1 + label_len > len) {
            break;
        }

        // 添加标签
        if (!domain.empty()) {
            domain += ".";
        }
        domain.append(reinterpret_cast<const char*>(data + offset + 1), label_len);
        offset += 1 + label_len;
    }

    // 如果跳转过，使用原始偏移量的后续位置
    if (jumped) {
        offset = orig_offset;
    }

    return domain;
}

} // namespace decoders
} // namespace netguardian
