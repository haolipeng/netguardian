#ifndef NETGUARDIAN_MATCHERS_NETWORK_MATCHER_H
#define NETGUARDIAN_MATCHERS_NETWORK_MATCHER_H

#include "matchers/matcher.h"
#include "rules/rule.h"
#include <arpa/inet.h>
#include <cstring>

namespace netguardian {
namespace matchers {

// IP 地址匹配器
class IpMatcher {
public:
    IpMatcher(const rules::IpAddress& ip_rule)
        : ip_rule_(ip_rule)
    {
        parse_cidr();
    }

    // 匹配 IPv4 地址
    bool match(uint32_t ip_addr) const {
        if (ip_rule_.is_any) {
            return !ip_rule_.is_negated;
        }

        bool matched = false;

        if (cidr_valid_) {
            // CIDR 匹配
            matched = (ip_addr & cidr_mask_) == (cidr_network_ & cidr_mask_);
        } else {
            // 精确匹配
            matched = (ip_addr == cidr_network_);
        }

        return ip_rule_.is_negated ? !matched : matched;
    }

    std::string description() const {
        return "IP matcher for: " + ip_rule_.to_string();
    }

private:
    rules::IpAddress ip_rule_;
    uint32_t cidr_network_;     // 网络地址
    uint32_t cidr_mask_;        // 子网掩码
    bool cidr_valid_;           // 是否为有效的 CIDR

    // 解析 CIDR 表示法（例如：192.168.1.0/24）
    void parse_cidr() {
        cidr_valid_ = false;

        if (ip_rule_.is_any) {
            return;
        }

        std::string addr_str = ip_rule_.address;
        size_t slash_pos = addr_str.find('/');

        if (slash_pos != std::string::npos) {
            // CIDR 格式
            std::string ip_part = addr_str.substr(0, slash_pos);
            std::string prefix_part = addr_str.substr(slash_pos + 1);

            struct in_addr addr;
            if (inet_pton(AF_INET, ip_part.c_str(), &addr) == 1) {
                cidr_network_ = addr.s_addr;

                try {
                    int prefix_len = std::stoi(prefix_part);
                    if (prefix_len >= 0 && prefix_len <= 32) {
                        if (prefix_len == 0) {
                            cidr_mask_ = 0;
                        } else {
                            cidr_mask_ = htonl(~((1u << (32 - prefix_len)) - 1));
                        }
                        cidr_valid_ = true;
                    }
                } catch (...) {
                    // 无效的前缀长度
                }
            }
        } else {
            // 单个 IP 地址
            struct in_addr addr;
            if (inet_pton(AF_INET, addr_str.c_str(), &addr) == 1) {
                cidr_network_ = addr.s_addr;
                cidr_mask_ = 0xFFFFFFFF;
                cidr_valid_ = true;
            }
        }
    }
};

// 端口匹配器
class PortMatcher {
public:
    PortMatcher(const rules::PortRange& port_rule)
        : port_rule_(port_rule)
    {}

    // 匹配端口
    bool match(uint16_t port) const {
        return port_rule_.matches(port);
    }

    std::string description() const {
        return "Port matcher for: " + port_rule_.to_string();
    }

private:
    rules::PortRange port_rule_;
};

// TCP 标志匹配器
class TcpFlagsMatcher {
public:
    // TCP 标志
    enum Flags {
        FIN = 0x01,
        SYN = 0x02,
        RST = 0x04,
        PSH = 0x08,
        ACK = 0x10,
        URG = 0x20,
        ECE = 0x40,
        CWR = 0x80
    };

    TcpFlagsMatcher(const std::string& flags_str)
        : required_flags_(0)
        , forbidden_flags_(0)
        , any_flag_(false)
    {
        parse_flags(flags_str);
    }

    // 匹配 TCP 标志
    bool match(uint8_t tcp_flags) const {
        if (any_flag_) {
            return true;
        }

        // 检查必须设置的标志
        if ((tcp_flags & required_flags_) != required_flags_) {
            return false;
        }

        // 检查必须不设置的标志
        if ((tcp_flags & forbidden_flags_) != 0) {
            return false;
        }

        return true;
    }

    std::string description() const {
        return "TCP flags matcher";
    }

private:
    uint8_t required_flags_;    // 必须设置的标志
    uint8_t forbidden_flags_;   // 必须不设置的标志
    bool any_flag_;             // 匹配任意标志

    // 解析标志字符串
    // 格式：S (SYN), A (ACK), F (FIN), R (RST), P (PSH), U (URG)
    // 前缀 ! 表示标志必须不设置
    void parse_flags(const std::string& flags_str) {
        if (flags_str.empty() || flags_str == "*") {
            any_flag_ = true;
            return;
        }

        for (size_t i = 0; i < flags_str.length(); ++i) {
            char ch = flags_str[i];
            bool negated = false;

            // 检查是否为取反标志
            if (ch == '!' && i + 1 < flags_str.length()) {
                negated = true;
                ++i;
                ch = flags_str[i];
            }

            uint8_t flag = 0;
            switch (ch) {
                case 'S': case 's': flag = SYN; break;
                case 'A': case 'a': flag = ACK; break;
                case 'F': case 'f': flag = FIN; break;
                case 'R': case 'r': flag = RST; break;
                case 'P': case 'p': flag = PSH; break;
                case 'U': case 'u': flag = URG; break;
                case 'E': case 'e': flag = ECE; break;
                case 'C': case 'c': flag = CWR; break;
                default: continue;
            }

            if (negated) {
                forbidden_flags_ |= flag;
            } else {
                required_flags_ |= flag;
            }
        }
    }
};

} // namespace matchers
} // namespace netguardian

#endif // NETGUARDIAN_MATCHERS_NETWORK_MATCHER_H
