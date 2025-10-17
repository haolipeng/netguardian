#ifndef NETGUARDIAN_MATCHERS_RULE_MATCHER_H
#define NETGUARDIAN_MATCHERS_RULE_MATCHER_H

#include "matchers/matcher.h"
#include "matchers/content_matcher.h"
#include "matchers/pcre_matcher.h"
#include "matchers/network_matcher.h"
#include "rules/rule.h"
#include "core/packet.h"
#include "decoders/protocol_headers.h"
#include <memory>
#include <vector>

namespace netguardian {
namespace matchers {

// 规则匹配结果
struct RuleMatchResult {
    bool matched;                   // 是否匹配
    uint32_t rule_sid;              // 匹配的规则 SID
    std::string rule_message;       // 规则消息
    rules::RuleAction action;       // 规则动作
    std::vector<MatchResult> content_matches;  // 内容匹配详情

    RuleMatchResult() : matched(false), rule_sid(0), action(rules::RuleAction::ALERT) {}
};

// 规则匹配引擎
// 将规则应用到数据包上，判断是否匹配
class RuleMatcher {
public:
    // 构造函数
    explicit RuleMatcher(const rules::Rule& rule)
        : rule_(rule)
    {
        compile();
    }

    // 匹配数据包
    RuleMatchResult match_packet(const core::Packet& packet) const {
        RuleMatchResult result;
        result.rule_sid = rule_.sid();
        result.rule_message = rule_.message();
        result.action = rule_.header().action;

        // 1. 检查协议
        if (!match_protocol(packet)) {
            return result;
        }

        // 2. 检查 IP 地址和端口
        if (!match_network(packet)) {
            return result;
        }

        // 3. 检查 TCP 标志（如果是 TCP）
        if (!match_tcp_flags(packet)) {
            return result;
        }

        // 4. 检查内容匹配
        if (!match_content(packet, result.content_matches)) {
            return result;
        }

        // 所有条件都匹配
        result.matched = true;
        return result;
    }

    const rules::Rule& rule() const { return rule_; }

private:
    const rules::Rule& rule_;                       // 规则引用
    std::vector<MatcherPtr> content_matchers_;      // 内容匹配器列表
    std::unique_ptr<TcpFlagsMatcher> tcp_flags_matcher_;  // TCP 标志匹配器

    // 编译规则（准备匹配器）
    void compile() {
        // 编译内容匹配器
        auto content_options = rule_.get_options(rules::RuleOptionType::CONTENT);
        bool nocase = rule_.get_option(rules::RuleOptionType::NOCASE).has_value();

        for (const auto& opt : content_options) {
            if (opt.has_value && !opt.value.empty()) {
                content_matchers_.push_back(
                    std::make_shared<ContentMatcher>(opt.value, !nocase)
                );
            }
        }

        // 编译正则表达式匹配器
        auto pcre_option = rule_.get_option(rules::RuleOptionType::PCRE);
        if (pcre_option.has_value() && pcre_option->has_value) {
            bool nocase_pcre = rule_.get_option(rules::RuleOptionType::NOCASE).has_value();
            content_matchers_.push_back(
                std::make_shared<PcreMatcher>(pcre_option->value, !nocase_pcre)
            );
        }

        // 编译 TCP 标志匹配器
        auto flags_option = rule_.get_option(rules::RuleOptionType::FLAGS);
        if (flags_option.has_value() && flags_option->has_value) {
            tcp_flags_matcher_ = std::make_unique<TcpFlagsMatcher>(flags_option->value);
        }
    }

    // 匹配协议
    bool match_protocol(const core::Packet& packet) const {
        const auto& header = rule_.header();
        const auto& stack = packet.protocol_stack();

        // 检查 L4 协议
        switch (header.protocol) {
            case rules::RuleProtocol::TCP:
                return stack.l4_type == core::ProtocolType::TCP;
            case rules::RuleProtocol::UDP:
                return stack.l4_type == core::ProtocolType::UDP;
            case rules::RuleProtocol::ICMP:
                return stack.l4_type == core::ProtocolType::ICMP;
            case rules::RuleProtocol::IP:
                return stack.l3_type == core::ProtocolType::IPV4;
            case rules::RuleProtocol::ANY:
                return true;
            default:
                return false;
        }
    }

    // 匹配网络层（IP 地址和端口）
    bool match_network(const core::Packet& packet) const {
        const auto& header = rule_.header();
        const auto& stack = packet.protocol_stack();

        // 检查是否有 IPv4 头部
        if (stack.l3_type != core::ProtocolType::IPV4 ||
            static_cast<size_t>(stack.l3_offset) + sizeof(decoders::IPv4Header) > packet.length()) {
            return false;
        }

        const decoders::IPv4Header* ip_hdr = reinterpret_cast<const decoders::IPv4Header*>(
            packet.data() + stack.l3_offset
        );

        // 匹配源 IP
        IpMatcher src_ip_matcher(header.src_ip);
        if (!src_ip_matcher.match(ip_hdr->src_ip)) {
            return false;
        }

        // 匹配目标 IP
        IpMatcher dst_ip_matcher(header.dst_ip);
        if (!dst_ip_matcher.match(ip_hdr->dst_ip)) {
            return false;
        }

        // 匹配端口（TCP/UDP）
        if (stack.l4_type == core::ProtocolType::TCP) {
            if (static_cast<size_t>(stack.l4_offset) + sizeof(decoders::TcpHeader) > packet.length()) {
                return false;
            }

            const decoders::TcpHeader* tcp_hdr = reinterpret_cast<const decoders::TcpHeader*>(
                packet.data() + stack.l4_offset
            );

            PortMatcher src_port_matcher(header.src_port);
            PortMatcher dst_port_matcher(header.dst_port);

            if (!src_port_matcher.match(ntohs(tcp_hdr->src_port)) ||
                !dst_port_matcher.match(ntohs(tcp_hdr->dst_port))) {
                return false;
            }

        } else if (stack.l4_type == core::ProtocolType::UDP) {
            if (static_cast<size_t>(stack.l4_offset) + sizeof(decoders::UdpHeader) > packet.length()) {
                return false;
            }

            const decoders::UdpHeader* udp_hdr = reinterpret_cast<const decoders::UdpHeader*>(
                packet.data() + stack.l4_offset
            );

            PortMatcher src_port_matcher(header.src_port);
            PortMatcher dst_port_matcher(header.dst_port);

            if (!src_port_matcher.match(ntohs(udp_hdr->src_port)) ||
                !dst_port_matcher.match(ntohs(udp_hdr->dst_port))) {
                return false;
            }
        }

        return true;
    }

    // 匹配 TCP 标志
    bool match_tcp_flags(const core::Packet& packet) const {
        if (!tcp_flags_matcher_) {
            return true;  // 没有 TCP 标志要求
        }

        const auto& stack = packet.protocol_stack();

        if (stack.l4_type != core::ProtocolType::TCP) {
            return false;
        }

        if (static_cast<size_t>(stack.l4_offset) + sizeof(decoders::TcpHeader) > packet.length()) {
            return false;
        }

        const decoders::TcpHeader* tcp_hdr = reinterpret_cast<const decoders::TcpHeader*>(
            packet.data() + stack.l4_offset
        );

        return tcp_flags_matcher_->match(tcp_hdr->flags);
    }

    // 匹配内容
    bool match_content(const core::Packet& packet, std::vector<MatchResult>& matches) const {
        if (content_matchers_.empty()) {
            return true;  // 没有内容匹配要求
        }

        // 获取 payload（应用层数据）
        const auto& stack = packet.protocol_stack();
        if (stack.l7_offset < 0 || static_cast<size_t>(stack.l7_offset) >= packet.length()) {
            return false;  // 没有应用层数据
        }

        const uint8_t* payload = packet.data() + stack.l7_offset;
        size_t payload_length = packet.length() - stack.l7_offset;

        // 所有内容匹配器都必须匹配
        for (const auto& matcher : content_matchers_) {
            MatchResult result = matcher->match(payload, payload_length);
            if (!result.matched) {
                return false;
            }
            matches.push_back(result);
        }

        return true;
    }
};

} // namespace matchers
} // namespace netguardian

#endif // NETGUARDIAN_MATCHERS_RULE_MATCHER_H
