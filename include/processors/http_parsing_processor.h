#ifndef NETGUARDIAN_PROCESSORS_HTTP_PARSING_PROCESSOR_H
#define NETGUARDIAN_PROCESSORS_HTTP_PARSING_PROCESSOR_H

#include "core/packet_processor.h"
#include "core/packet_context.h"
#include "decoders/http_parser.h"
#include <memory>

namespace netguardian {
namespace processors {

/**
 * HttpParsingProcessor - HTTP 解析处理器
 *
 * 职责：
 * - 检测 HTTP 流量（基于端口）
 * - 解析 HTTP 请求和响应
 * - 将解析结果附加到 PacketContext
 * - 记录 HTTP 统计
 *
 * 注意：
 * - 只解析 TCP 流量
 * - 需要在 ProtocolParsingProcessor 之后运行
 */
class HttpParsingProcessor : public core::PacketProcessor {
public:
    HttpParsingProcessor() = default;

    const char* name() const override {
        return "HttpParsingProcessor";
    }

    core::ProcessResult process(core::PacketContext& ctx) override {
        const auto& stack = ctx.packet().protocol_stack();

        // 只处理 TCP
        if (stack.l4_type != core::ProtocolType::TCP) {
            return core::ProcessResult::CONTINUE;
        }

        // 检查是否有 payload
        if (stack.payload_len == 0) {
            return core::ProcessResult::CONTINUE;
        }

        // 检查是否是 HTTP 端口
        if (!is_http_port(ctx)) {
            return core::ProcessResult::CONTINUE;
        }

        const uint8_t* payload = ctx.packet().data() + stack.payload_offset;
        size_t payload_len = stack.payload_len;

        // 尝试解析 HTTP 请求
        auto request = std::make_shared<decoders::HttpRequest>();
        int req_result = decoders::HttpParser::parse_request(payload, payload_len, *request);
        if (req_result > 0) {
            ctx.set_http_request(request);
            ctx.stats().record_http();
            return core::ProcessResult::CONTINUE;
        }

        // 尝试解析 HTTP 响应
        auto response = std::make_shared<decoders::HttpResponse>();
        int resp_result = decoders::HttpParser::parse_response(payload, payload_len, *response);
        if (resp_result > 0) {
            ctx.set_http_response(response);
            ctx.stats().record_http();
            return core::ProcessResult::CONTINUE;
        }

        // 不是有效的 HTTP 消息
        return core::ProcessResult::CONTINUE;
    }

private:
    /**
     * 检查是否是 HTTP 端口
     */
    bool is_http_port(const core::PacketContext& ctx) const {
        // 如果有流信息，使用流的端口
        if (ctx.has_flow()) {
            const auto& key = ctx.flow()->key();
            return key.src_port == 80 || key.src_port == 8080 ||
                   key.dst_port == 80 || key.dst_port == 8080;
        }

        // 否则从数据包中提取端口
        const auto& stack = ctx.packet().protocol_stack();
        if (stack.l4_type != core::ProtocolType::TCP ||
            static_cast<size_t>(stack.l4_offset) + sizeof(decoders::TcpHeader) > ctx.packet().length()) {
            return false;
        }

        const auto* tcp_hdr = reinterpret_cast<const decoders::TcpHeader*>(
            ctx.packet().data() + stack.l4_offset
        );

        uint16_t src_port = ntohs(tcp_hdr->src_port);
        uint16_t dst_port = ntohs(tcp_hdr->dst_port);

        return src_port == 80 || src_port == 8080 ||
               dst_port == 80 || dst_port == 8080;
    }
};

} // namespace processors
} // namespace netguardian

#endif // NETGUARDIAN_PROCESSORS_HTTP_PARSING_PROCESSOR_H
