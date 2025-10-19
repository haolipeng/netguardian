#ifndef NETGUARDIAN_PROCESSORS_TCP_REASSEMBLY_PROCESSOR_H
#define NETGUARDIAN_PROCESSORS_TCP_REASSEMBLY_PROCESSOR_H

#include "core/packet_processor.h"
#include "core/packet_context.h"
#include "core/protocol_types.h"
#include "flow/flow.h"
#include "flow/flow_key.h"
#include <memory>

namespace netguardian {
namespace processors {

/**
 * TcpReassemblyProcessor - TCP 流重组处理器
 *
 * 职责：
 * - 将 TCP 段添加到流的重组器中
 * - 处理乱序、重叠、重传等问题
 * - 为上层应用提供重组后的连续数据流
 *
 * 依赖：
 * - 需要 FlowTrackingProcessor 先创建流
 * - 需要 ProtocolParsingProcessor 先解析协议
 *
 * 设计模式：
 * - Strategy Pattern: 可配置不同的重叠处理策略
 * - Chain of Responsibility: 作为管道的一部分
 *
 * SOLID 原则：
 * - SRP: 只负责 TCP 流重组
 * - OCP: 可扩展重叠策略，无需修改
 * - DIP: 依赖 Flow 抽象，而非具体实现
 */
class TcpReassemblyProcessor : public core::PacketProcessor {
public:
    /**
     * 构造函数
     */
    TcpReassemblyProcessor() = default;

    /**
     * 析构函数
     */
    ~TcpReassemblyProcessor() override = default;

    /**
     * 获取处理器名称
     */
    const char* name() const override {
        return "TcpReassemblyProcessor";
    }

    /**
     * 初始化处理器
     */
    bool initialize() override {
        return true;
    }

    /**
     * 处理数据包
     *
     * @param ctx 数据包上下文
     * @return ProcessResult::CONTINUE - 继续处理
     *         ProcessResult::STOP - 停止处理（不丢弃）
     */
    core::ProcessResult process(core::PacketContext& ctx) override {
        auto& packet = ctx.packet();
        const auto& stack = packet.protocol_stack();

        // 只处理 TCP 数据包
        if (stack.l4_type() != core::ProtocolType::TCP) {
            return core::ProcessResult::CONTINUE;
        }

        // 需要有流信息
        auto flow = ctx.flow();
        if (!flow) {
            return core::ProcessResult::CONTINUE;
        }

        // 只处理有负载的数据包
        if (stack.payload_len() == 0) {
            return core::ProcessResult::CONTINUE;
        }

        // Use cached TCP fields
        if (stack.l4.length < 20) {
            return core::ProcessResult::CONTINUE;
        }

        // 解析 TCP 序列号 - use cached field
        uint32_t seq = stack.l4.seq;

        // 获取负载数据
        const uint8_t* payload = packet.data() + stack.payload_offset();
        uint16_t payload_len = stack.payload_len();

        // 确定流方向
        flow::FlowDirection direction = determine_flow_direction(packet, flow);

        // 添加段到重组器
        flow->add_tcp_segment(direction, seq, payload, payload_len);

        // 记录统计信息（可选）
        ctx.stats().record_tcp_segment();

        return core::ProcessResult::CONTINUE;
    }

    /**
     * 关闭处理器
     */
    void shutdown() override {
        // 无需清理
    }

    /**
     * 刷新缓冲区
     */
    void flush() override {
        // TCP 重组器在流超时时自动刷新
    }

private:
    /**
     * 确定流方向
     *
     * @param packet 数据包
     * @param flow 流对象
     * @return 流方向
     */
    flow::FlowDirection determine_flow_direction(
        const core::Packet& packet,
        std::shared_ptr<flow::Flow> flow) const
    {
        const auto& stack = packet.protocol_stack();
        const flow::FlowKey& flow_key = flow->key();

        // Use cached fields from ProtocolStack
        uint32_t src_ip = stack.l3.src_ip;
        uint16_t src_port = stack.l4.src_port;

        // 比较源 IP 和端口
        if (src_ip == flow_key.src_ip && src_port == flow_key.src_port) {
            return flow::FlowDirection::FORWARD;
        } else {
            return flow::FlowDirection::REVERSE;
        }
    }
};

} // namespace processors
} // namespace netguardian

#endif // NETGUARDIAN_PROCESSORS_TCP_REASSEMBLY_PROCESSOR_H
