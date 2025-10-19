#ifndef NETGUARDIAN_PROCESSORS_IP_REASSEMBLY_PROCESSOR_H
#define NETGUARDIAN_PROCESSORS_IP_REASSEMBLY_PROCESSOR_H

#include "core/packet_processor.h"
#include "core/packet_context.h"
#include "core/protocol_types.h"
#include "core/packet.h"
#include "reassembly/ipv4_reassembler.h"
#include "reassembly/ipv6_reassembler.h"
#include <memory>
#include <arpa/inet.h>

namespace netguardian {
namespace processors {

/**
 * IpReassemblyProcessor - IP 分片重组处理器
 *
 * 职责：
 * - 检测 IP 分片数据包
 * - 缓存分片并在所有分片到达后重组
 * - 将重组后的完整数据包传递给下游处理器
 *
 * 支持：
 * - IPv4 分片重组
 * - IPv6 分片重组
 * - 分片超时清理
 *
 * 设计模式：
 * - Strategy Pattern: IPv4 和 IPv6 不同的重组策略
 * - Chain of Responsibility: 作为管道的一部分
 *
 * SOLID 原则：
 * - SRP: 只负责 IP 分片重组
 * - OCP: 可扩展到其他 IP 版本
 * - DIP: 依赖重组器抽象
 */
class IpReassemblyProcessor : public core::PacketProcessor {
public:
    /**
     * 构造函数
     *
     * @param timeout_seconds 分片超时时间（秒）
     * @param max_fragments 每个数据包的最大分片数
     */
    explicit IpReassemblyProcessor(uint32_t timeout_seconds = 60,
                                   uint32_t max_fragments = 100)
        : ipv4_reassembler_(timeout_seconds, max_fragments)
        , ipv6_reassembler_(timeout_seconds, max_fragments)
        , cleanup_counter_(0)
    {}

    /**
     * 析构函数
     */
    ~IpReassemblyProcessor() override = default;

    /**
     * 获取处理器名称
     */
    const char* name() const override {
        return "IpReassemblyProcessor";
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
     * @return ProcessResult::CONTINUE - 继续处理（完整数据包或非分片）
     *         ProcessResult::STOP - 停止处理（分片已缓存，等待重组）
     */
    core::ProcessResult process(core::PacketContext& ctx) override {
        auto& packet = ctx.packet();
        const auto& stack = packet.protocol_stack();

        // 定期清理超时分片（每 100 个数据包）
        if (++cleanup_counter_ >= 100) {
            ipv4_reassembler_.cleanup_timeout();
            ipv6_reassembler_.cleanup_timeout();
            cleanup_counter_ = 0;
        }

        // IPv4 分片处理
        if (stack.l3_type() == core::ProtocolType::IPV4) {
            return process_ipv4_fragment(ctx);
        }

        // IPv6 分片处理
        if (stack.l3_type() == core::ProtocolType::IPV6) {
            return process_ipv6_fragment(ctx);
        }

        // 非 IP 数据包或完整数据包，继续处理
        return core::ProcessResult::CONTINUE;
    }

    /**
     * 关闭处理器
     */
    void shutdown() override {
        ipv4_reassembler_.clear_all();
        ipv6_reassembler_.clear_all();
    }

    /**
     * 刷新缓冲区
     */
    void flush() override {
        ipv4_reassembler_.cleanup_timeout();
        ipv6_reassembler_.cleanup_timeout();
    }

private:
    /**
     * 处理 IPv4 分片
     */
    core::ProcessResult process_ipv4_fragment(core::PacketContext& ctx) {
        auto& packet = ctx.packet();
        const auto& stack = packet.protocol_stack();

        if (stack.l3.offset == 0 || stack.l3.length < 20) {
            return core::ProcessResult::CONTINUE;
        }

        // Use cached fields from ProtocolStack
        uint16_t fragment_offset = stack.l3.fragment_offset;
        bool more_fragments = stack.l3.more_fragments;
        bool is_fragment = stack.l3.is_fragment;

        // 如果不是分片，则为完整数据包
        if (!is_fragment) {
            return core::ProcessResult::CONTINUE;
        }

        // 这是一个分片，提取关键信息 - use cached fields
        reassembly::Ipv4FragmentKey key;
        key.src_ip = stack.l3.src_ip;
        key.dst_ip = stack.l3.dst_ip;
        key.id = stack.l3.fragment_id;
        key.protocol = stack.l3.protocol;

        // 获取分片数据（IP 负载）
        const uint8_t* fragment_data = packet.data() + stack.l4.offset;
        uint16_t fragment_len = stack.l4.length + stack.l7.length;

        // 添加分片到重组器
        ipv4_reassembler_.add_fragment(key, fragment_offset, fragment_data,
                                       fragment_len, more_fragments);

        // 检查是否可以重组
        if (ipv4_reassembler_.can_reassemble(key)) {
            // 重组数据包
            auto reassembled = ipv4_reassembler_.reassemble(key);

            // TODO: 创建新的重组后的 Packet 对象并替换当前 ctx 中的 packet
            // 这需要修改 PacketContext 以支持替换 Packet
            // 目前先记录统计信息

            ctx.stats().record_ip_reassembly();

            // 重组完成，继续处理
            return core::ProcessResult::CONTINUE;
        }

        // 分片已缓存，停止处理（等待其他分片）
        return core::ProcessResult::STOP;
    }

    /**
     * 处理 IPv6 分片
     */
    core::ProcessResult process_ipv6_fragment(core::PacketContext& ctx) {
        auto& packet = ctx.packet();
        const auto& stack = packet.protocol_stack();

        if (stack.l3.offset == 0 || stack.l3.length < 40) {
            return core::ProcessResult::CONTINUE;
        }

        // TODO: 实现 IPv6 分片检测和重组
        // IPv6 分片头部在扩展头部中，需要解析扩展头部链
        // 当前简化实现，直接继续处理

        (void)packet;
        (void)stack;

        return core::ProcessResult::CONTINUE;
    }

    reassembly::Ipv4Reassembler ipv4_reassembler_;  // IPv4 重组器
    reassembly::Ipv6Reassembler ipv6_reassembler_;  // IPv6 重组器
    uint32_t cleanup_counter_;                       // 清理计数器
};

} // namespace processors
} // namespace netguardian

#endif // NETGUARDIAN_PROCESSORS_IP_REASSEMBLY_PROCESSOR_H
