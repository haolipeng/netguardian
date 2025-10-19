#ifndef NETGUARDIAN_PROCESSORS_RULE_DETECTION_PROCESSOR_H
#define NETGUARDIAN_PROCESSORS_RULE_DETECTION_PROCESSOR_H

#include "core/packet_processor.h"
#include "core/packet_context.h"
#include "rules/rule_manager.h"
#include "matchers/rule_matcher.h"
#include "alerts/alert_manager.h"
#include "decoders/packet_info.h"
#include <memory>
#include <vector>
#include <unordered_map>
#include <arpa/inet.h>

namespace netguardian {
namespace processors {

/**
 * RuleDetectionProcessor - 规则检测处理器
 *
 * 职责：
 * - 将规则应用到数据包上进行匹配
 * - 生成告警（Alert）
 * - 执行规则动作（alert/drop/pass/log）
 *
 * 依赖：
 * - RuleManager: 管理规则集
 * - RuleMatcher: 执行规则匹配
 * - AlertManager: 处理告警输出
 *
 * 设计模式：
 * - Strategy Pattern: 不同的规则匹配策略
 * - Observer Pattern: 告警通知
 * - Chain of Responsibility: 作为管道的一部分
 *
 * SOLID 原则：
 * - SRP: 只负责规则检测和告警生成
 * - OCP: 可扩展规则类型和匹配器
 * - DIP: 依赖 RuleManager 和 AlertManager 抽象
 */
class RuleDetectionProcessor : public core::PacketProcessor {
public:
    /**
     * 构造函数
     *
     * @param rule_manager 规则管理器（共享）
     * @param alert_manager 告警管理器（共享）
     */
    explicit RuleDetectionProcessor(
        std::shared_ptr<rules::RuleManager> rule_manager,
        std::shared_ptr<alerts::AlertManager> alert_manager)
        : rule_manager_(rule_manager)
        , alert_manager_(alert_manager)
        , matchers_compiled_(false)
    {}

    /**
     * 析构函数
     */
    ~RuleDetectionProcessor() override = default;

    /**
     * 获取处理器名称
     */
    const char* name() const override {
        return "RuleDetectionProcessor";
    }

    /**
     * 初始化处理器
     */
    bool initialize() override {
        if (!rule_manager_) {
            return false;
        }

        // 编译所有启用的规则
        compile_matchers();

        return true;
    }

    /**
     * 处理数据包
     *
     * @param ctx 数据包上下文
     * @return ProcessResult::CONTINUE - 继续处理（alert/log）
     *         ProcessResult::DROP - 丢弃数据包（drop）
     *         ProcessResult::STOP - 停止处理（pass）
     */
    core::ProcessResult process(core::PacketContext& ctx) override {
        if (!matchers_compiled_) {
            compile_matchers();
        }

        if (matchers_.empty()) {
            return core::ProcessResult::CONTINUE;
        }

        auto& packet = ctx.packet();

        // 遍历所有规则匹配器
        for (const auto& matcher : matchers_) {
            auto result = matcher->match_packet(packet);

            if (result.matched) {
                // 规则匹配成功
                ctx.stats().record_rule_match();

                // 根据规则动作处理
                switch (result.action) {
                    case rules::RuleAction::ALERT:
                        // 生成告警并继续处理
                        generate_alert(ctx, result);
                        break;

                    case rules::RuleAction::LOG:
                        // 记录日志并继续处理
                        generate_alert(ctx, result);
                        break;

                    case rules::RuleAction::DROP:
                        // 生成告警并丢弃数据包
                        generate_alert(ctx, result);
                        return core::ProcessResult::DROP;

                    case rules::RuleAction::PASS:
                        // 放行数据包，停止后续规则检测
                        return core::ProcessResult::STOP;

                    case rules::RuleAction::REJECT:
                        // 拒绝数据包（生成 RST 或 ICMP unreachable）
                        generate_alert(ctx, result);
                        return core::ProcessResult::DROP;

                    default:
                        break;
                }
            }
        }

        return core::ProcessResult::CONTINUE;
    }

    /**
     * 关闭处理器
     */
    void shutdown() override {
        matchers_.clear();
        matchers_compiled_ = false;
    }

    /**
     * 刷新缓冲区
     */
    void flush() override {
        if (alert_manager_) {
            alert_manager_->flush();
        }
    }

    /**
     * 重新编译规则匹配器
     */
    void reload_rules() {
        compile_matchers();
    }

    /**
     * 获取匹配器数量
     */
    size_t matcher_count() const {
        return matchers_.size();
    }

private:
    std::shared_ptr<rules::RuleManager> rule_manager_;      // 规则管理器
    std::shared_ptr<alerts::AlertManager> alert_manager_;   // 告警管理器
    std::vector<std::shared_ptr<matchers::RuleMatcher>> matchers_;  // 规则匹配器列表
    bool matchers_compiled_;                                 // 是否已编译

    /**
     * 编译规则匹配器
     */
    void compile_matchers() {
        matchers_.clear();

        if (!rule_manager_) {
            matchers_compiled_ = false;
            return;
        }

        // 获取所有启用的规则
        auto rules = rule_manager_->get_enabled_rules();

        // 为每条规则创建匹配器
        for (const auto& rule : rules) {
            if (rule) {
                matchers_.push_back(
                    std::make_shared<matchers::RuleMatcher>(*rule)
                );
            }
        }

        matchers_compiled_ = true;
    }

    /**
     * 生成告警
     */
    void generate_alert(core::PacketContext& ctx, const matchers::RuleMatchResult& match_result) {
        if (!alert_manager_ || !rule_manager_) {
            return;
        }

        // 获取规则
        auto rule = rule_manager_->get_rule(match_result.rule_sid);
        if (!rule) {
            return;
        }

        // 从 Packet 提取 PacketInfo
        decoders::PacketInfo packet_info = extract_packet_info(ctx.packet());

        // 使用 AlertGenerator 创建告警
        auto& generator = alert_manager_->get_generator();
        auto alert = generator.generate_alert(*rule, packet_info);

        // 提交到 AlertManager 处理
        alert_manager_->process_alert(alert);

        // 记录统计信息
        ctx.stats().record_alert();
    }

    /**
     * 从 Packet 提取 PacketInfo
     */
    decoders::PacketInfo extract_packet_info(const core::Packet& packet) const {
        decoders::PacketInfo info;
        const auto& stack = packet.protocol_stack();

        // 数据包长度
        info.packet_length = packet.length();

        // Use cached fields from new ProtocolStack structure
        // IPv4 信息
        if (stack.l3_type() == core::ProtocolType::IPV4) {
            info.has_ipv4 = true;
            info.ipv4_src = stack.l3.src_ip;
            info.ipv4_dst = stack.l3.dst_ip;
            info.ipv4_ttl = stack.l3.ttl;
        }

        // TCP 信息
        if (stack.l4_type() == core::ProtocolType::TCP) {
            info.has_tcp = true;
            info.tcp_src_port = stack.l4.src_port;
            info.tcp_dst_port = stack.l4.dst_port;

            uint8_t flags = stack.l4.flags;
            info.tcp_flags_syn = (flags & 0x02) != 0;
            info.tcp_flags_ack = (flags & 0x10) != 0;
            info.tcp_flags_fin = (flags & 0x01) != 0;
            info.tcp_flags_rst = (flags & 0x04) != 0;
            info.tcp_flags_psh = (flags & 0x08) != 0;
            info.tcp_flags_urg = (flags & 0x20) != 0;
        }

        // UDP 信息
        if (stack.l4_type() == core::ProtocolType::UDP) {
            info.has_udp = true;
            info.udp_src_port = stack.l4.src_port;
            info.udp_dst_port = stack.l4.dst_port;
        }

        // ICMP 信息
        if (stack.l4_type() == core::ProtocolType::ICMP) {
            info.has_icmp = true;
        }

        return info;
    }
};

} // namespace processors
} // namespace netguardian

#endif // NETGUARDIAN_PROCESSORS_RULE_DETECTION_PROCESSOR_H
