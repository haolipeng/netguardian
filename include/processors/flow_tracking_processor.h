#ifndef NETGUARDIAN_PROCESSORS_FLOW_TRACKING_PROCESSOR_H
#define NETGUARDIAN_PROCESSORS_FLOW_TRACKING_PROCESSOR_H

#include "core/packet_processor.h"
#include "core/packet_context.h"
#include "flow/flow_table.h"
#include "flow/flow_manager.h"
#include "decoders/protocol_headers.h"
#include <memory>
#include <arpa/inet.h>

namespace netguardian {
namespace processors {

/**
 * FlowTrackingProcessor - 流跟踪处理器
 *
 * 职责：
 * - 提取流键（FlowKey）
 * - 查找或创建流
 * - 更新流状态（TCP 状态机、计数器等）
 * - 将流信息附加到 PacketContext
 * - 记录流统计
 *
 * 注意：
 * - 只处理 TCP/UDP 流
 * - 不负责流的超时管理（由 FlowManager 定期处理）
 */
class FlowTrackingProcessor : public core::PacketProcessor {
public:
    /**
     * 构造函数
     *
     * @param flow_table 流表（共享）
     */
    explicit FlowTrackingProcessor(std::shared_ptr<flow::FlowTable> flow_table)
        : flow_table_(flow_table)
    {}

    const char* name() const override {
        return "FlowTrackingProcessor";
    }

    core::ProcessResult process(core::PacketContext& ctx) override {
        const auto& stack = ctx.packet().protocol_stack();

        // 只处理 TCP/UDP
        if (stack.l4_type != core::ProtocolType::TCP &&
            stack.l4_type != core::ProtocolType::UDP) {
            return core::ProcessResult::CONTINUE;
        }

        // 提取流键
        flow::FlowKey key = extract_flow_key(ctx.packet());

        // 更新流表
        flow_table_->update_flow(key, static_cast<uint32_t>(ctx.packet().length()));

        // 获取或创建流
        auto flow_ptr = flow_table_->get_or_create_flow(key);
        if (!flow_ptr) {
            // 流表已满或其他错误
            return core::ProcessResult::CONTINUE;
        }

        // 处理 TCP 状态
        if (stack.l4_type == core::ProtocolType::TCP) {
            process_tcp_flow(ctx, flow_ptr, key);
        }

        // 将流附加到上下文
        ctx.set_flow(flow_ptr);

        // 更新流统计
        auto flow_stats = flow_table_->get_stats();
        ctx.stats().set_active_flows(flow_stats.active_flows);

        return core::ProcessResult::CONTINUE;
    }

private:
    /**
     * 提取流键
     */
    flow::FlowKey extract_flow_key(const core::Packet& packet) const {
        flow::FlowKey key;
        const auto& stack = packet.protocol_stack();

        // 提取 IP 地址
        if (stack.l3_type == core::ProtocolType::IPV4 &&
            static_cast<size_t>(stack.l3_offset) + sizeof(decoders::IPv4Header) <= packet.length()) {

            const auto* ip_hdr = reinterpret_cast<const decoders::IPv4Header*>(
                packet.data() + stack.l3_offset
            );

            key.src_ip = ip_hdr->src_ip;
            key.dst_ip = ip_hdr->dst_ip;
            key.protocol = ip_hdr->protocol;
        }

        // 提取端口
        if (stack.l4_type == core::ProtocolType::TCP &&
            static_cast<size_t>(stack.l4_offset) + sizeof(decoders::TcpHeader) <= packet.length()) {

            const auto* tcp_hdr = reinterpret_cast<const decoders::TcpHeader*>(
                packet.data() + stack.l4_offset
            );

            key.src_port = ntohs(tcp_hdr->src_port);
            key.dst_port = ntohs(tcp_hdr->dst_port);

        } else if (stack.l4_type == core::ProtocolType::UDP &&
                   static_cast<size_t>(stack.l4_offset) + sizeof(decoders::UdpHeader) <= packet.length()) {

            const auto* udp_hdr = reinterpret_cast<const decoders::UdpHeader*>(
                packet.data() + stack.l4_offset
            );

            key.src_port = ntohs(udp_hdr->src_port);
            key.dst_port = ntohs(udp_hdr->dst_port);
        }

        return key;
    }

    /**
     * 处理 TCP 流状态
     */
    void process_tcp_flow(core::PacketContext& ctx,
                          std::shared_ptr<flow::Flow> flow_ptr,
                          const flow::FlowKey& key) {
        const auto& stack = ctx.packet().protocol_stack();

        if (static_cast<size_t>(stack.l4_offset) + sizeof(decoders::TcpHeader) > ctx.packet().length()) {
            return;
        }

        const auto* tcp_hdr = reinterpret_cast<const decoders::TcpHeader*>(
            ctx.packet().data() + stack.l4_offset
        );

        // 提取 TCP 标志
        flow::TcpFlags flags = flow::TcpFlags::from_header(tcp_hdr);

        // 判断方向
        bool is_initiator = (flow_ptr->get_direction(key) == flow::FlowDirection::FORWARD);

        // 更新 TCP 状态
        flow_ptr->process_tcp_packet(
            flags,
            ntohl(tcp_hdr->seq_num),
            ntohl(tcp_hdr->ack_num),
            is_initiator
        );
    }

    std::shared_ptr<flow::FlowTable> flow_table_;
};

} // namespace processors
} // namespace netguardian

#endif // NETGUARDIAN_PROCESSORS_FLOW_TRACKING_PROCESSOR_H
