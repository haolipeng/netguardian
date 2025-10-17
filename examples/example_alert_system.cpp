/*
 * Alert System Example
 *
 * 演示告警系统功能：
 * 1. 告警生成
 * 2. 多种输出格式（控制台、JSON、CSV、Syslog）
 * 3. 告警优先级管理
 * 4. 告警去重
 * 5. 告警统计
 */

#include "alerts/alert.h"
#include "alerts/alert_generator.h"
#include "alerts/alert_output.h"
#include "alerts/alert_manager.h"
#include "rules/rule.h"
#include "decoders/packet_info.h"
#include <iostream>
#include <thread>
#include <chrono>

using namespace netguardian;
using namespace netguardian::alerts;
using namespace netguardian::rules;
using namespace netguardian::decoders;

// 创建测试数据包信息
PacketInfo create_test_packet(const std::string& src_ip, const std::string& dst_ip,
                               uint16_t src_port, uint16_t dst_port) {
    PacketInfo packet;

    packet.packet_length = 1500;
    packet.has_ethernet = true;
    packet.has_ipv4 = true;
    packet.has_tcp = true;

    // 解析 IP 地址
    struct in_addr addr;
    inet_aton(src_ip.c_str(), &addr);
    packet.ipv4_src = addr.s_addr;
    inet_aton(dst_ip.c_str(), &addr);
    packet.ipv4_dst = addr.s_addr;

    packet.ipv4_ttl = 64;
    packet.tcp_src_port = src_port;
    packet.tcp_dst_port = dst_port;
    packet.tcp_flags_syn = true;
    packet.tcp_flags_ack = false;

    return packet;
}

// 创建测试规则
Rule create_test_rule(uint32_t sid, const std::string& msg, int priority,
                      const std::string& classtype = "attempted-recon") {
    Rule rule;
    rule.set_sid(sid);
    rule.set_rev(1);
    rule.set_message(msg);
    rule.set_priority(priority);
    rule.set_classtype(classtype);

    // 设置规则头部
    rule.header().action = RuleAction::ALERT;
    rule.header().protocol = RuleProtocol::TCP;

    // 添加 reference 选项
    rule.add_option(RuleOption(RuleOptionType::REFERENCE, "reference", "cve,2021-12345"));

    return rule;
}

// 测试 1：基本告警生成
void test_basic_alert_generation() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 1: Basic Alert Generation                      ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝\n" << std::endl;

    AlertGenerator generator;

    // 创建规则和数据包
    auto rule = create_test_rule(1000001, "HTTP SQL Injection Attempt", 2, "web-attack");
    auto packet = create_test_packet("192.168.1.100", "10.0.0.50", 45678, 80);

    // 生成告警
    auto alert = generator.generate_alert(rule, packet, {"' OR '1'='1", "UNION SELECT"});

    std::cout << "Generated Alert:" << std::endl;
    std::cout << "  ID: " << alert->alert_id << std::endl;
    std::cout << "  Message: " << alert->message << std::endl;
    std::cout << "  Priority: " << priority_to_string(alert->priority) << std::endl;
    std::cout << "  Category: " << category_to_string(alert->category) << std::endl;
    std::cout << "  Source: " << alert->src_ip << ":" << alert->src_port << std::endl;
    std::cout << "  Destination: " << alert->dst_ip << ":" << alert->dst_port << std::endl;
    std::cout << "  Matched Patterns: ";
    for (const auto& pattern : alert->matched_patterns) {
        std::cout << "\"" << pattern << "\" ";
    }
    std::cout << std::endl;
}

// 测试 2：多种输出格式
void test_output_formats() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 2: Multiple Output Formats                     ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝\n" << std::endl;

    AlertGenerator generator;
    auto rule = create_test_rule(1000002, "Port Scan Detected", 3, "scan");
    auto packet = create_test_packet("172.16.0.50", "192.168.1.10", 54321, 22);
    auto alert = generator.generate_alert(rule, packet);

    // 1. 文本格式
    std::cout << "\n--- Text Format ---" << std::endl;
    std::cout << alert->to_string() << std::endl;

    // 2. JSON 格式
    std::cout << "\n--- JSON Format ---" << std::endl;
    std::cout << alert->to_json() << std::endl;

    // 3. CSV 格式
    std::cout << "\n--- CSV Format ---" << std::endl;
    std::cout << Alert::csv_header() << std::endl;
    std::cout << alert->to_csv() << std::endl;
}

// 测试 3：文件输出
void test_file_output() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 3: File Output                                 ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝\n" << std::endl;

    AlertGenerator generator;

    // 创建不同格式的文件输出器
    auto text_output = std::make_shared<FileAlertOutput>(
        "/tmp/netguardian_alerts.txt", FileAlertOutput::FileFormat::TEXT);
    auto json_output = std::make_shared<FileAlertOutput>(
        "/tmp/netguardian_alerts.json", FileAlertOutput::FileFormat::JSON);
    auto csv_output = std::make_shared<FileAlertOutput>(
        "/tmp/netguardian_alerts.csv", FileAlertOutput::FileFormat::CSV);

    std::cout << "Writing alerts to files..." << std::endl;

    // 生成多个告警并写入文件
    for (int i = 1; i <= 5; i++) {
        auto rule = create_test_rule(1000000 + i,
                                     "Test Alert " + std::to_string(i),
                                     (i % 4) + 1);
        auto packet = create_test_packet("192.168.1." + std::to_string(i),
                                        "10.0.0." + std::to_string(i),
                                        10000 + i, 80);
        auto alert = generator.generate_alert(rule, packet);

        text_output->output(*alert);
        json_output->output(*alert);
        csv_output->output(*alert);
    }

    text_output->close();
    json_output->close();
    csv_output->close();

    std::cout << "Alerts written to:" << std::endl;
    std::cout << "  /tmp/netguardian_alerts.txt" << std::endl;
    std::cout << "  /tmp/netguardian_alerts.json" << std::endl;
    std::cout << "  /tmp/netguardian_alerts.csv" << std::endl;
}

// 测试 4：告警管理器和去重
void test_alert_manager_deduplication() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 4: Alert Manager & Deduplication               ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝\n" << std::endl;

    AlertManager manager;

    // 配置去重：60 秒窗口，每条规则最多 3 个告警
    DeduplicationConfig dedup_config;
    dedup_config.enabled = true;
    dedup_config.time_window_seconds = 60;
    dedup_config.max_alerts_per_rule = 3;
    manager.set_deduplication_config(dedup_config);

    // 添加控制台输出
    auto console_output = std::make_shared<ConsoleAlertOutput>();
    manager.add_output(console_output);

    std::cout << "Deduplication Config:" << std::endl;
    std::cout << "  Time Window: " << dedup_config.time_window_seconds << " seconds" << std::endl;
    std::cout << "  Max Alerts Per Rule: " << dedup_config.max_alerts_per_rule << std::endl;
    std::cout << "\nGenerating 10 alerts for the same rule..." << std::endl;

    // 生成 10 个相同规则的告警
    auto rule = create_test_rule(2000001, "Repeated Attack Detected", 2);
    auto packet = create_test_packet("192.168.1.100", "10.0.0.50", 45678, 80);

    for (int i = 1; i <= 10; i++) {
        auto alert = manager.get_generator().generate_alert(rule, packet);
        manager.process_alert(alert);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "\n--- Statistics ---" << std::endl;
    std::cout << manager.get_statistics().to_string() << std::endl;
    std::cout << "\nNote: Only " << dedup_config.max_alerts_per_rule
              << " alerts were output, " << (10 - dedup_config.max_alerts_per_rule)
              << " were suppressed due to deduplication." << std::endl;
}

// 测试 5：优先级处理
void test_priority_handling() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 5: Priority Handling                           ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝\n" << std::endl;

    AlertManager manager;

    // 添加彩色控制台输出
    auto console_output = std::make_shared<ConsoleAlertOutput>(
        ConsoleAlertOutput::ColorMode::BASIC);
    manager.add_output(console_output);

    // 禁用去重以便看到所有告警
    DeduplicationConfig dedup_config;
    dedup_config.enabled = false;
    manager.set_deduplication_config(dedup_config);

    std::cout << "Generating alerts with different priorities:" << std::endl;
    std::cout << "(Colors indicate priority: Critical=Red, High=Red, Medium=Yellow, Low=Cyan)\n" << std::endl;

    // 生成不同优先级的告警
    struct {
        int priority;
        std::string msg;
        std::string classtype;
    } test_cases[] = {
        {1, "Critical System Compromise Detected", "exploit"},
        {2, "High Priority Malware Activity", "malware"},
        {3, "Medium Priority Policy Violation", "policy"},
        {4, "Low Priority Suspicious Activity", "suspicious"}
    };

    for (const auto& tc : test_cases) {
        auto rule = create_test_rule(3000000 + tc.priority, tc.msg, tc.priority, tc.classtype);
        auto packet = create_test_packet("192.168.1.100", "10.0.0.50", 12345, 443);
        auto alert = manager.get_generator().generate_alert(rule, packet);
        manager.process_alert(alert);
    }

    std::cout << "\n--- Statistics ---" << std::endl;
    std::cout << manager.get_statistics().to_string() << std::endl;
}

// 测试 6：组合输出
void test_multi_output() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 6: Multiple Outputs Simultaneously             ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝\n" << std::endl;

    AlertManager manager;

    // 添加多个输出器
    auto console_output = std::make_shared<ConsoleAlertOutput>();
    auto file_output = std::make_shared<FileAlertOutput>(
        "/tmp/netguardian_multi_output.json", FileAlertOutput::FileFormat::JSON);

    manager.add_output(console_output);
    manager.add_output(file_output);

    std::cout << "Configured outputs: Console + JSON File" << std::endl;
    std::cout << "Generating alerts...\n" << std::endl;

    // 生成几个告警
    for (int i = 1; i <= 3; i++) {
        auto rule = create_test_rule(4000000 + i, "Multi-Output Test " + std::to_string(i), 2);
        auto packet = create_test_packet("192.168.1." + std::to_string(i),
                                        "10.0.0." + std::to_string(i),
                                        20000 + i, 443);
        auto alert = manager.get_generator().generate_alert(rule, packet);
        manager.process_alert(alert);
    }

    manager.close();

    std::cout << "\nAlerts have been written to both console and file:" << std::endl;
    std::cout << "  /tmp/netguardian_multi_output.json" << std::endl;
}

int main() {
    std::cout << "\n╔════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║       NetGuardian Alert System Demo                   ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════╝" << std::endl;

    try {
        // 运行所有测试
        test_basic_alert_generation();
        test_output_formats();
        test_file_output();
        test_alert_manager_deduplication();
        test_priority_handling();
        test_multi_output();

        std::cout << "\n╔════════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║  All tests completed successfully!                    ║" << std::endl;
        std::cout << "╚════════════════════════════════════════════════════════╝\n" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
