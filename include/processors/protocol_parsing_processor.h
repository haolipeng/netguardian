#ifndef NETGUARDIAN_PROCESSORS_PROTOCOL_PARSING_PROCESSOR_H
#define NETGUARDIAN_PROCESSORS_PROTOCOL_PARSING_PROCESSOR_H

#include "core/packet_processor.h"
#include "core/packet_context.h"
#include "core/protocol_parser.h"
#include <pcap/pcap.h>

namespace netguardian {
namespace processors {

/**
 * ProtocolParsingProcessor - 协议解析处理器
 *
 * 职责：
 * - 解析 L2-L4 协议栈（以太网、IP、TCP/UDP）
 * - 更新数据包的 protocol_stack 信息
 * - 记录协议统计
 *
 * 注意：
 * - 这个处理器只做基本的协议解析，不做深度解析
 * - L7 协议解析由其他专用处理器负责（HttpParsingProcessor、DnsParsingProcessor）
 */
class ProtocolParsingProcessor : public core::PacketProcessor {
public:
    /**
     * 构造函数
     *
     * @param datalink_type Datalink 类型（如 DLT_EN10MB）
     */
    explicit ProtocolParsingProcessor(int datalink_type = DLT_EN10MB)
        : datalink_type_(datalink_type)
    {}

    const char* name() const override {
        return "ProtocolParsingProcessor";
    }

    core::ProcessResult process(core::PacketContext& ctx) override {
        // 使用 ProtocolParser 解析协议栈
        if (!core::ProtocolParser::parse(ctx.packet(), datalink_type_)) {
            // 解析失败，记录并丢弃
            ctx.stats().record_dropped_packet();
            return core::ProcessResult::DROP;
        }

        // 记录协议统计
        ctx.stats().record_protocols(ctx.packet().protocol_stack());

        return core::ProcessResult::CONTINUE;
    }

private:
    int datalink_type_;  // Datalink 类型
};

} // namespace processors
} // namespace netguardian

#endif // NETGUARDIAN_PROCESSORS_PROTOCOL_PARSING_PROCESSOR_H
