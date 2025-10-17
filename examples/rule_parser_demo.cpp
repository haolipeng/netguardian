#include "rules/rule.h"
#include "rules/rule_parser.h"
#include "rules/rule_manager.h"
#include "core/version.h"

#include <iostream>
#include <iomanip>

using namespace netguardian;
using namespace netguardian::rules;

void print_separator() {
    std::cout << std::string(80, '=') << "\n";
}

void print_rule_details(const Rule& rule) {
    print_separator();
    std::cout << "【规则详情】\n";
    print_separator();

    std::cout << "规则 ID (SID):     " << rule.sid() << "\n";
    std::cout << "版本 (REV):        " << rule.rev() << "\n";
    std::cout << "消息:              " << rule.message() << "\n";
    std::cout << "优先级:            " << rule.priority() << "\n";
    std::cout << "分类:              " << rule.classtype() << "\n";
    std::cout << "启用:              " << (rule.enabled() ? "是" : "否") << "\n\n";

    std::cout << "规则头部:\n";
    std::cout << "  动作:            " << action_to_string(rule.header().action) << "\n";
    std::cout << "  协议:            " << protocol_to_string(rule.header().protocol) << "\n";
    std::cout << "  源地址:          " << rule.header().src_ip.to_string() << "\n";
    std::cout << "  源端口:          " << rule.header().src_port.to_string() << "\n";
    std::cout << "  方向:            " << direction_to_string(rule.header().direction) << "\n";
    std::cout << "  目标地址:        " << rule.header().dst_ip.to_string() << "\n";
    std::cout << "  目标端口:        " << rule.header().dst_port.to_string() << "\n\n";

    std::cout << "规则选项 (" << rule.options().size() << " 个):\n";
    for (const auto& opt : rule.options()) {
        std::cout << "  - " << opt.to_string() << "\n";
    }

    std::cout << "\n重构的规则:\n";
    std::cout << "  " << rule.to_string() << "\n";

    std::cout << "\n原始规则:\n";
    std::cout << "  " << rule.raw_text() << "\n\n";
}

void print_manager_stats(const RuleManager& manager) {
    print_separator();
    std::cout << "【规则管理器统计】\n";
    print_separator();

    auto stats = manager.get_stats();

    std::cout << "总规则数:          " << stats.total_rules << "\n";
    std::cout << "启用规则数:        " << stats.enabled_rules << "\n";
    std::cout << "禁用规则数:        " << stats.disabled_rules << "\n\n";

    std::cout << "按动作分类:\n";
    std::cout << "  ALERT:           " << stats.alert_rules << "\n";
    std::cout << "  LOG:             " << stats.log_rules << "\n";
    std::cout << "  DROP:            " << stats.drop_rules << "\n";
    std::cout << "  PASS:            " << stats.pass_rules << "\n\n";
}

int main() {
    std::cout << "╔════════════════════════════════════════════╗\n";
    std::cout << "║    NetGuardian 规则解析器演示             ║\n";
    std::cout << "║    版本 " << VERSION << "                          ║\n";
    std::cout << "╚════════════════════════════════════════════╝\n\n";

    // 示例规则
    std::string example_rules = R"(
# 这是注释行
alert tcp any any -> any 80 (msg:"HTTP GET Request"; content:"GET"; sid:1000001; rev:1;)
alert tcp any any -> any 443 (msg:"HTTPS Traffic"; content:"TLS"; sid:1000002; rev:1; priority:2; classtype:web-application-attack;)
alert udp any any -> any 53 (msg:"DNS Query"; content:"query"; sid:1000003; rev:1;)
log tcp any any -> 192.168.1.0/24 22 (msg:"SSH Connection"; content:"SSH"; sid:1000004; rev:1;)
drop tcp any any -> any 23 (msg:"Telnet Detected"; content:"telnet"; nocase; sid:1000005; rev:2; priority:1;)
alert tcp any any -> any 3306 (msg:"MySQL Connection"; content:"mysql"; sid:1000006; rev:1;)
alert tcp any any -> any any (msg:"SQL Injection Attempt"; content:"UNION SELECT"; nocase; sid:1000007; rev:1; priority:1; classtype:web-application-attack;)
)";

    // 创建规则解析器
    RuleParser parser;

    std::cout << "【测试 1：解析单条规则】\n";
    print_separator();

    std::string single_rule = "alert tcp any any -> any 80 (msg:\"HTTP GET Request\"; content:\"GET\"; sid:1000001; rev:1;)";
    std::cout << "解析规则: " << single_rule << "\n\n";

    auto rule = parser.parse_rule(single_rule);
    if (rule) {
        print_rule_details(*rule);
    } else {
        std::cout << "解析失败！\n";
        for (const auto& error : parser.errors()) {
            std::cout << error.to_string() << "\n";
        }
    }

    std::cout << "\n\n【测试 2：解析多条规则】\n";
    print_separator();

    parser.clear_errors();
    auto rules = parser.parse_rules(example_rules);

    std::cout << "成功解析规则: " << parser.total_parsed() << "\n";
    std::cout << "解析失败: " << parser.total_failed() << "\n\n";

    if (parser.has_errors()) {
        std::cout << "解析错误:\n";
        for (const auto& error : parser.errors()) {
            std::cout << "  - " << error.to_string() << "\n";
        }
        std::cout << "\n";
    }

    std::cout << "解析成功的规则列表:\n";
    for (size_t i = 0; i < rules.size(); ++i) {
        const auto& r = rules[i];
        std::cout << "  " << (i + 1) << ". [SID:" << r->sid() << "] "
                  << r->message() << "\n";
        std::cout << "     " << action_to_string(r->header().action) << " "
                  << protocol_to_string(r->header().protocol) << " "
                  << r->header().dst_port.to_string() << "\n";
    }

    std::cout << "\n\n【测试 3：规则管理器】\n";
    print_separator();

    RuleManager manager;

    std::cout << "加载规则到管理器...\n";
    if (manager.load_rules_string(example_rules)) {
        std::cout << "✓ 规则加载成功\n\n";
    } else {
        std::cout << "✗ 规则加载失败\n";
        for (const auto& error : manager.get_parse_errors()) {
            std::cout << "  - " << error.to_string() << "\n";
        }
    }

    print_manager_stats(manager);

    // 测试按协议查询
    std::cout << "【测试 4：按协议查询规则】\n";
    print_separator();

    auto tcp_rules = manager.get_rules_by_protocol(RuleProtocol::TCP);
    std::cout << "TCP 规则数量: " << tcp_rules.size() << "\n";
    for (const auto& r : tcp_rules) {
        std::cout << "  - [SID:" << r->sid() << "] " << r->message() << "\n";
    }
    std::cout << "\n";

    auto udp_rules = manager.get_rules_by_protocol(RuleProtocol::UDP);
    std::cout << "UDP 规则数量: " << udp_rules.size() << "\n";
    for (const auto& r : udp_rules) {
        std::cout << "  - [SID:" << r->sid() << "] " << r->message() << "\n";
    }

    // 测试规则启用/禁用
    std::cout << "\n\n【测试 5：启用/禁用规则】\n";
    print_separator();

    uint32_t test_sid = 1000001;
    std::cout << "禁用规则 SID:" << test_sid << "...\n";
    if (manager.disable_rule(test_sid)) {
        auto r = manager.get_rule(test_sid);
        std::cout << "✓ 规则已禁用，状态: " << (r->enabled() ? "启用" : "禁用") << "\n";
    }

    std::cout << "\n启用规则 SID:" << test_sid << "...\n";
    if (manager.enable_rule(test_sid)) {
        auto r = manager.get_rule(test_sid);
        std::cout << "✓ 规则已启用，状态: " << (r->enabled() ? "启用" : "禁用") << "\n";
    }

    std::cout << "\n\n";
    print_manager_stats(manager);

    // 测试按动作查询
    std::cout << "【测试 6：按动作查询规则】\n";
    print_separator();

    auto alert_rules = manager.get_rules_by_action(RuleAction::ALERT);
    std::cout << "ALERT 规则数量: " << alert_rules.size() << "\n";
    for (const auto& r : alert_rules) {
        std::cout << "  - [SID:" << r->sid() << "] " << r->message() << "\n";
    }
    std::cout << "\n";

    auto drop_rules = manager.get_rules_by_action(RuleAction::DROP);
    std::cout << "DROP 规则数量: " << drop_rules.size() << "\n";
    for (const auto& r : drop_rules) {
        std::cout << "  - [SID:" << r->sid() << "] " << r->message() << "\n";
    }

    std::cout << "\n";
    print_separator();
    std::cout << "【演示完成】\n";
    print_separator();

    return 0;
}
