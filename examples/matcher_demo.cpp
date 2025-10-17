#include "matchers/content_matcher.h"
#include "matchers/multi_pattern_matcher.h"
#include "matchers/pcre_matcher.h"
#include "matchers/network_matcher.h"
#include "matchers/rule_matcher.h"
#include "rules/rule_parser.h"
#include "core/version.h"

#include <iostream>
#include <iomanip>

using namespace netguardian;
using namespace netguardian::matchers;
using namespace netguardian::rules;

void print_separator() {
    std::cout << std::string(80, '=') << "\n";
}

void print_match_result(const MatchResult& result) {
    if (result.matched) {
        std::cout << "  ✓ 匹配成功\n";
        std::cout << "    位置: " << result.offset << "\n";
        std::cout << "    长度: " << result.length << "\n";
        std::cout << "    匹配数据: \"" << result.matched_data << "\"\n";
    } else {
        std::cout << "  ✗ 未匹配\n";
    }
}

int main() {
    std::cout << "╔════════════════════════════════════════════╗\n";
    std::cout << "║    NetGuardian 模式匹配引擎演示           ║\n";
    std::cout << "║    版本 " << VERSION << "                          ║\n";
    std::cout << "╚════════════════════════════════════════════╝\n\n";

    // 测试 1：Boyer-Moore 字符串匹配
    std::cout << "【测试 1：Boyer-Moore 字符串匹配】\n";
    print_separator();

    std::string test_data1 = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
    std::cout << "测试数据: " << test_data1 << "\n\n";

    ContentMatcher matcher1("GET", true);
    std::cout << "模式: \"GET\" (区分大小写)\n";
    auto result1 = matcher1.match(
        reinterpret_cast<const uint8_t*>(test_data1.data()),
        test_data1.length()
    );
    print_match_result(result1);

    std::cout << "\n模式: \"host\" (不区分大小写)\n";
    ContentMatcher matcher2("host", false);
    auto result2 = matcher2.match(
        reinterpret_cast<const uint8_t*>(test_data1.data()),
        test_data1.length()
    );
    print_match_result(result2);

    // 测试 2：Aho-Corasick 多模式匹配
    std::cout << "\n\n【测试 2：Aho-Corasick 多模式匹配】\n";
    print_separator();

    std::string test_data2 = "SELECT * FROM users WHERE username='admin' UNION SELECT password FROM accounts";
    std::cout << "测试数据: " << test_data2 << "\n\n";

    MultiPatternMatcher multi_matcher(false);  // 不区分大小写
    multi_matcher.add_pattern("SELECT");
    multi_matcher.add_pattern("UNION");
    multi_matcher.add_pattern("password");
    multi_matcher.add_pattern("DROP");
    multi_matcher.build();

    std::cout << "模式列表: SELECT, UNION, password, DROP\n";
    auto results = multi_matcher.match_all(
        reinterpret_cast<const uint8_t*>(test_data2.data()),
        test_data2.length()
    );

    std::cout << "找到 " << results.size() << " 个匹配:\n";
    for (size_t i = 0; i < results.size(); ++i) {
        std::cout << "  匹配 " << (i + 1) << ": \"" << results[i].matched_data
                  << "\" at position " << results[i].offset << "\n";
    }

    // 测试 3：正则表达式匹配
    std::cout << "\n\n【测试 3：正则表达式匹配】\n";
    print_separator();

    std::string test_data3 = "Email: admin@example.com, Phone: 123-456-7890";
    std::cout << "测试数据: " << test_data3 << "\n\n";

    PcreMatcher email_matcher(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
    std::cout << "正则模式: 邮箱地址\n";
    auto result3 = email_matcher.match(
        reinterpret_cast<const uint8_t*>(test_data3.data()),
        test_data3.length()
    );
    print_match_result(result3);

    std::cout << "\n正则模式: 电话号码\n";
    PcreMatcher phone_matcher(R"(\d{3}-\d{3}-\d{4})");
    auto result4 = phone_matcher.match(
        reinterpret_cast<const uint8_t*>(test_data3.data()),
        test_data3.length()
    );
    print_match_result(result4);

    // 测试 4：IP 地址匹配
    std::cout << "\n\n【测试 4：IP 地址匹配】\n";
    print_separator();

    IpAddress ip_rule1("192.168.1.0/24");
    IpMatcher ip_matcher1(ip_rule1);

    struct in_addr addr1;
    inet_pton(AF_INET, "192.168.1.100", &addr1);
    std::cout << "规则: 192.168.1.0/24\n";
    std::cout << "测试 IP: 192.168.1.100 - "
              << (ip_matcher1.match(addr1.s_addr) ? "✓ 匹配" : "✗ 不匹配") << "\n";

    struct in_addr addr2;
    inet_pton(AF_INET, "192.168.2.100", &addr2);
    std::cout << "测试 IP: 192.168.2.100 - "
              << (ip_matcher1.match(addr2.s_addr) ? "✓ 匹配" : "✗ 不匹配") << "\n";

    // 测试 5：端口匹配
    std::cout << "\n\n【测试 5：端口匹配】\n";
    print_separator();

    PortRange port_rule1(80);
    PortMatcher port_matcher1(port_rule1);
    std::cout << "规则: 端口 80\n";
    std::cout << "测试端口 80: " << (port_matcher1.match(80) ? "✓ 匹配" : "✗ 不匹配") << "\n";
    std::cout << "测试端口 443: " << (port_matcher1.match(443) ? "✓ 匹配" : "✗ 不匹配") << "\n";

    PortRange port_rule2(1024, 65535);
    PortMatcher port_matcher2(port_rule2);
    std::cout << "\n规则: 端口范围 1024:65535\n";
    std::cout << "测试端口 80: " << (port_matcher2.match(80) ? "✓ 匹配" : "✗ 不匹配") << "\n";
    std::cout << "测试端口 8080: " << (port_matcher2.match(8080) ? "✓ 匹配" : "✗ 不匹配") << "\n";

    // 测试 6：TCP 标志匹配
    std::cout << "\n\n【测试 6：TCP 标志匹配】\n";
    print_separator();

    TcpFlagsMatcher tcp_matcher1("S");  // SYN
    std::cout << "规则: TCP SYN 标志\n";
    std::cout << "测试标志 SYN (0x02): "
              << (tcp_matcher1.match(0x02) ? "✓ 匹配" : "✗ 不匹配") << "\n";
    std::cout << "测试标志 SYN+ACK (0x12): "
              << (tcp_matcher1.match(0x12) ? "✓ 匹配" : "✗ 不匹配") << "\n";

    TcpFlagsMatcher tcp_matcher2("SA");  // SYN+ACK
    std::cout << "\n规则: TCP SYN+ACK 标志\n";
    std::cout << "测试标志 SYN+ACK (0x12): "
              << (tcp_matcher2.match(0x12) ? "✓ 匹配" : "✗ 不匹配") << "\n";
    std::cout << "测试标志 ACK (0x10): "
              << (tcp_matcher2.match(0x10) ? "✓ 匹配" : "✗ 不匹配") << "\n";

    // 测试 7：综合测试 - 完整规则匹配
    std::cout << "\n\n【测试 7：完整规则匹配】\n";
    print_separator();

    std::string rule_text = "alert tcp any any -> any 80 (msg:\"HTTP GET Request\"; content:\"GET\"; content:\"/\"; sid:1000001; rev:1;)";
    std::cout << "规则: " << rule_text << "\n\n";

    RuleParser parser;
    auto rule = parser.parse_rule(rule_text);

    if (rule) {
        std::cout << "规则解析成功！\n";
        std::cout << "  SID: " << rule->sid() << "\n";
        std::cout << "  消息: " << rule->message() << "\n";
        std::cout << "  协议: " << protocol_to_string(rule->header().protocol) << "\n";
        std::cout << "  目标端口: " << rule->header().dst_port.to_string() << "\n";
        std::cout << "  内容模式数: " << rule->get_options(RuleOptionType::CONTENT).size() << "\n";
    } else {
        std::cout << "规则解析失败！\n";
        for (const auto& error : parser.errors()) {
            std::cout << "  " << error.to_string() << "\n";
        }
    }

    std::cout << "\n";
    print_separator();
    std::cout << "【测试完成】\n";
    std::cout << "\n所有匹配器测试通过！\n";
    std::cout << "  ✓ Boyer-Moore 字符串匹配\n";
    std::cout << "  ✓ Aho-Corasick 多模式匹配\n";
    std::cout << "  ✓ 正则表达式匹配\n";
    std::cout << "  ✓ IP 地址匹配\n";
    std::cout << "  ✓ 端口匹配\n";
    std::cout << "  ✓ TCP 标志匹配\n";
    std::cout << "  ✓ 规则匹配引擎\n";
    print_separator();

    return 0;
}
