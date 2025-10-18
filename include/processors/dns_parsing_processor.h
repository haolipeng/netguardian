#ifndef NETGUARDIAN_PROCESSORS_DNS_PARSING_PROCESSOR_H
#define NETGUARDIAN_PROCESSORS_DNS_PARSING_PROCESSOR_H

#include "core/packet_processor.h"
#include "core/packet_context.h"
#include "decoders/dns_parser.h"
#include <memory>

namespace netguardian {
namespace processors {

/**
 * DnsParsingProcessor - DNS 解析处理器
 *
 * 职责：
 * - 检测 DNS 流量（基于端口）
 * - 解析 DNS 消息
 * - 将解析结果附加到 PacketContext
 * - 记录 DNS 统计
 *
 * 注意：
 * - 主要处理 UDP 流量（DNS over UDP）
 * - 需要在 ProtocolParsingProcessor 之后运行
 */
class DnsParsingProcessor : public core::PacketProcessor {
public:
    DnsParsingProcessor() = default;

    const char* name() const override {
        return "DnsParsingProcessor";
    }

    core::ProcessResult process(core::PacketContext& ctx) override {
        const auto& stack = ctx.packet().protocol_stack();

        // 只处理 UDP（DNS 主要使用 UDP）
        if (stack.l4_type != core::ProtocolType::UDP) {
            return core::ProcessResult::CONTINUE;
        }

        // 检查是否有 payload
        if (stack.payload_len == 0) {
            return core::ProcessResult::CONTINUE;
        }

        // 检查是否是 DNS 端口（53）
        if (!is_dns_port(ctx)) {
            return core::ProcessResult::CONTINUE;
        }

        const uint8_t* payload = ctx.packet().data() + stack.payload_offset;
        size_t payload_len = stack.payload_len;

        // 尝试解析 DNS 消息
        auto message = std::make_shared<decoders::DnsMessage>();
        int result = decoders::DnsParser::parse_message(payload, payload_len, *message);

        if (result > 0) {
            ctx.set_dns_message(message);
            ctx.stats().record_dns();
        }

        return core::ProcessResult::CONTINUE;
    }

private:
    /**
     * 检查是否是 DNS 端口
     */
    bool is_dns_port(const core::PacketContext& ctx) const {
        // 如果有流信息，使用流的端口
        if (ctx.has_flow()) {
            const auto& key = ctx.flow()->key();
            return key.src_port == 53 || key.dst_port == 53;
        }

        // 否则从数据包中提取端口
        const auto& stack = ctx.packet().protocol_stack();
        if (stack.l4_type != core::ProtocolType::UDP ||
            static_cast<size_t>(stack.l4_offset) + sizeof(decoders::UdpHeader) > ctx.packet().length()) {
            return false;
        }

        const auto* udp_hdr = reinterpret_cast<const decoders::UdpHeader*>(
            ctx.packet().data() + stack.l4_offset
        );

        uint16_t src_port = ntohs(udp_hdr->src_port);
        uint16_t dst_port = ntohs(udp_hdr->dst_port);

        return src_port == 53 || dst_port == 53;
    }
};

} // namespace processors
} // namespace netguardian

#endif // NETGUARDIAN_PROCESSORS_DNS_PARSING_PROCESSOR_H
