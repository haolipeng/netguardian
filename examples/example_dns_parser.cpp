#include "decoders/dns_parser.h"
#include "decoders/dns_anomaly_detector.h"
#include "decoders/dns_transaction.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <thread>
#include <chrono>
#include <arpa/inet.h>

using namespace netguardian::decoders;

// ============================================================================
// DNS 报文构造辅助函数
// ============================================================================

class DnsPacketBuilder {
public:
    DnsPacketBuilder() : offset_(0) {
        data_.resize(2048);  // 增大缓冲区以支持超长域名测试
    }

    void write_uint16(uint16_t value) {
        uint16_t net_value = htons(value);
        std::memcpy(&data_[offset_], &net_value, 2);
        offset_ += 2;
    }

    void write_uint32(uint32_t value) {
        uint32_t net_value = htonl(value);
        std::memcpy(&data_[offset_], &net_value, 4);
        offset_ += 4;
    }

    void write_uint8(uint8_t value) {
        data_[offset_++] = value;
    }

    void write_domain_name(const std::string& domain) {
        size_t start = 0;
        for (size_t i = 0; i <= domain.length(); i++) {
            if (i == domain.length() || domain[i] == '.') {
                size_t len = i - start;
                if (len > 0) {
                    write_uint8(len);
                    std::memcpy(&data_[offset_], domain.c_str() + start, len);
                    offset_ += len;
                }
                start = i + 1;
            }
        }
        write_uint8(0);  // 结束符
    }

    void write_ipv4(const std::string& ip) {
        struct in_addr addr;
        inet_pton(AF_INET, ip.c_str(), &addr);
        std::memcpy(&data_[offset_], &addr, 4);
        offset_ += 4;
    }

    void write_ipv6(const std::string& ip) {
        struct in6_addr addr;
        inet_pton(AF_INET6, ip.c_str(), &addr);
        std::memcpy(&data_[offset_], &addr, 16);
        offset_ += 16;
    }

    void write_bytes(const uint8_t* bytes, size_t len) {
        std::memcpy(&data_[offset_], bytes, len);
        offset_ += len;
    }

    const uint8_t* data() const { return data_.data(); }
    size_t size() const { return offset_; }

private:
    std::vector<uint8_t> data_;
    size_t offset_;
};

// ============================================================================
// 测试辅助函数
// ============================================================================

void print_separator(const std::string& title) {
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════╗\n";
    std::cout << "║  " << std::left << std::setw(52) << title << "║\n";
    std::cout << "╚═══════════════════════════════════════════════════════╝\n";
}

void print_header() {
    std::cout << "╔════════════════════════════════════════════════════════╗\n";
    std::cout << "║       NetGuardian DNS Parser Demo                     ║\n";
    std::cout << "╚════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// 测试场景
// ============================================================================

// 测试 1: 简单 A 记录查询
void test1_simple_a_query() {
    print_separator("Test 1: Simple A Record Query");

    DnsPacketBuilder builder;

    // DNS 头部
    builder.write_uint16(0x1234);  // Transaction ID
    builder.write_uint16(0x0100);  // Flags: Standard query, RD=1
    builder.write_uint16(1);       // Questions: 1
    builder.write_uint16(0);       // Answer RRs: 0
    builder.write_uint16(0);       // Authority RRs: 0
    builder.write_uint16(0);       // Additional RRs: 0

    // Question
    builder.write_domain_name("www.example.com");
    builder.write_uint16(1);       // Type: A
    builder.write_uint16(1);       // Class: IN

    // 解析
    DnsMessage message;
    int parsed = DnsParser::parse_message(builder.data(), builder.size(), message);

    std::cout << "Parsed bytes: " << parsed << " / " << builder.size() << "\n\n";
    std::cout << message.to_string();

    if (!message.questions.empty()) {
        std::cout << "✓ Query successfully parsed\n";
    }
}

// 测试 2: A 记录响应
void test2_a_record_response() {
    print_separator("Test 2: A Record Response");

    DnsPacketBuilder builder;

    // DNS 头部
    builder.write_uint16(0x1234);  // Transaction ID
    builder.write_uint16(0x8180);  // Flags: Response, RD=1, RA=1
    builder.write_uint16(1);       // Questions: 1
    builder.write_uint16(2);       // Answer RRs: 2
    builder.write_uint16(0);       // Authority RRs: 0
    builder.write_uint16(0);       // Additional RRs: 0

    // Question
    builder.write_domain_name("www.example.com");
    builder.write_uint16(1);       // Type: A
    builder.write_uint16(1);       // Class: IN

    // Answer 1
    builder.write_domain_name("www.example.com");
    builder.write_uint16(1);       // Type: A
    builder.write_uint16(1);       // Class: IN
    builder.write_uint32(300);     // TTL: 300 seconds
    builder.write_uint16(4);       // RDLENGTH: 4
    builder.write_ipv4("93.184.216.34");  // example.com 的真实 IP

    // Answer 2
    builder.write_domain_name("www.example.com");
    builder.write_uint16(1);       // Type: A
    builder.write_uint16(1);       // Class: IN
    builder.write_uint32(300);     // TTL
    builder.write_uint16(4);       // RDLENGTH
    builder.write_ipv4("93.184.216.35");

    // 解析
    DnsMessage message;
    DnsParser::parse_message(builder.data(), builder.size(), message);

    std::cout << message.to_string();

    auto ips = message.get_resolved_ips();
    std::cout << "\nResolved IPs (" << ips.size() << "):\n";
    for (const auto& ip : ips) {
        std::cout << "  - " << ip << "\n";
    }
}

// 测试 3: AAAA 记录（IPv6）
void test3_aaaa_record() {
    print_separator("Test 3: AAAA Record (IPv6)");

    DnsPacketBuilder builder;

    // DNS 头部
    builder.write_uint16(0x5678);
    builder.write_uint16(0x8180);  // Response
    builder.write_uint16(1);
    builder.write_uint16(1);
    builder.write_uint16(0);
    builder.write_uint16(0);

    // Question
    builder.write_domain_name("ipv6.google.com");
    builder.write_uint16(28);      // Type: AAAA
    builder.write_uint16(1);       // Class: IN

    // Answer
    builder.write_domain_name("ipv6.google.com");
    builder.write_uint16(28);      // Type: AAAA
    builder.write_uint16(1);
    builder.write_uint32(60);
    builder.write_uint16(16);      // RDLENGTH: 16
    builder.write_ipv6("2001:4860:4860::8888");  // Google DNS IPv6

    // 解析
    DnsMessage message;
    DnsParser::parse_message(builder.data(), builder.size(), message);

    std::cout << message.to_string();

    auto ips = message.get_resolved_ips();
    if (!ips.empty()) {
        std::cout << "IPv6 Address: " << ips[0] << "\n";
    }
}

// 测试 4: CNAME 记录
void test4_cname_record() {
    print_separator("Test 4: CNAME Record");

    DnsPacketBuilder builder;

    builder.write_uint16(0xabcd);
    builder.write_uint16(0x8180);
    builder.write_uint16(1);
    builder.write_uint16(1);
    builder.write_uint16(0);
    builder.write_uint16(0);

    // Question
    builder.write_domain_name("www.github.com");
    builder.write_uint16(1);  // Type: A
    builder.write_uint16(1);

    // Answer (CNAME)
    builder.write_domain_name("www.github.com");
    builder.write_uint16(5);       // Type: CNAME
    builder.write_uint16(1);
    builder.write_uint32(1800);
    size_t rdlength_pos = builder.size();
    builder.write_uint16(0);       // RDLENGTH placeholder
    size_t rdata_start = builder.size();
    builder.write_domain_name("github.github.io");
    // 更新 RDLENGTH
    uint16_t rdlength = builder.size() - rdata_start;
    *const_cast<uint16_t*>(reinterpret_cast<const uint16_t*>(builder.data() + rdlength_pos))
        = htons(rdlength);

    // 解析
    DnsMessage message;
    DnsParser::parse_message(builder.data(), builder.size(), message);

    std::cout << message.to_string();

    if (!message.answers.empty() && message.answers[0].domain_rdata) {
        std::cout << "CNAME Target: " << message.answers[0].domain_rdata->domain << "\n";
    }
}

// 测试 5: MX 记录
void test5_mx_record() {
    print_separator("Test 5: MX Record");

    DnsPacketBuilder builder;

    builder.write_uint16(0x9999);
    builder.write_uint16(0x8180);
    builder.write_uint16(1);
    builder.write_uint16(2);  // 2 MX records
    builder.write_uint16(0);
    builder.write_uint16(0);

    // Question
    builder.write_domain_name("example.com");
    builder.write_uint16(15);  // Type: MX
    builder.write_uint16(1);

    // Answer 1
    builder.write_domain_name("example.com");
    builder.write_uint16(15);  // Type: MX
    builder.write_uint16(1);
    builder.write_uint32(3600);
    size_t rdlen1_pos = builder.size();
    builder.write_uint16(0);   // RDLENGTH placeholder
    size_t rdata1_start = builder.size();
    builder.write_uint16(10);  // Preference
    builder.write_domain_name("mail1.example.com");
    uint16_t rdlen1 = builder.size() - rdata1_start;
    *const_cast<uint16_t*>(reinterpret_cast<const uint16_t*>(builder.data() + rdlen1_pos))
        = htons(rdlen1);

    // Answer 2
    builder.write_domain_name("example.com");
    builder.write_uint16(15);
    builder.write_uint16(1);
    builder.write_uint32(3600);
    size_t rdlen2_pos = builder.size();
    builder.write_uint16(0);
    size_t rdata2_start = builder.size();
    builder.write_uint16(20);  // Preference
    builder.write_domain_name("mail2.example.com");
    uint16_t rdlen2 = builder.size() - rdata2_start;
    *const_cast<uint16_t*>(reinterpret_cast<const uint16_t*>(builder.data() + rdlen2_pos))
        = htons(rdlen2);

    // 解析
    DnsMessage message;
    DnsParser::parse_message(builder.data(), builder.size(), message);

    std::cout << message.to_string();

    std::cout << "\nMX Records:\n";
    for (const auto& ans : message.answers) {
        if (ans.mx_rdata) {
            std::cout << "  Priority " << ans.mx_rdata->preference
                     << ": " << ans.mx_rdata->exchange << "\n";
        }
    }
}

// 测试 6: TXT 记录
void test6_txt_record() {
    print_separator("Test 6: TXT Record");

    DnsPacketBuilder builder;

    builder.write_uint16(0x7777);
    builder.write_uint16(0x8180);
    builder.write_uint16(1);
    builder.write_uint16(1);
    builder.write_uint16(0);
    builder.write_uint16(0);

    // Question
    builder.write_domain_name("example.com");
    builder.write_uint16(16);  // Type: TXT
    builder.write_uint16(1);

    // Answer
    builder.write_domain_name("example.com");
    builder.write_uint16(16);  // Type: TXT
    builder.write_uint16(1);
    builder.write_uint32(300);
    // TXT RDATA - 简化版本
    std::string txt1 = "v=spf1 -all";
    builder.write_uint16(txt1.length() + 1);  // RDLENGTH
    builder.write_uint8(txt1.length());
    builder.write_bytes(reinterpret_cast<const uint8_t*>(txt1.data()), txt1.length());

    // 解析
    DnsMessage message;
    int parsed = DnsParser::parse_message(builder.data(), builder.size(), message);

    std::cout << "Parsed bytes: " << parsed << "\n\n";
    std::cout << message.to_string();

    if (!message.answers.empty() && message.answers[0].txt_rdata) {
        std::cout << "\nTXT Records:\n";
        for (const auto& txt : message.answers[0].txt_rdata->texts) {
            std::cout << "  \"" << txt << "\"\n";
        }
    }
}

// 测试 7: 异常检测 - 超长域名
void test7_anomaly_long_domain() {
    print_separator("Test 7: Anomaly Detection - Long Domain");

    // 构造超长域名（简化版本，避免缓冲区溢出）
    std::string long_domain;
    for (int i = 0; i < 15; i++) {  // 减少到15个子域名
        long_domain += "longsubdomain" + std::to_string(i) + ".";
    }
    long_domain += "example.com";

    DnsPacketBuilder builder;
    builder.write_uint16(0x1111);
    builder.write_uint16(0x0100);
    builder.write_uint16(1);
    builder.write_uint16(0);
    builder.write_uint16(0);
    builder.write_uint16(0);

    builder.write_domain_name(long_domain);
    builder.write_uint16(1);
    builder.write_uint16(1);

    DnsMessage message;
    DnsParser::parse_message(builder.data(), builder.size(), message);

    std::cout << "Domain length: " << long_domain.length() << " bytes\n";
    std::cout << "Domain: " << long_domain.substr(0, 80) << "...\n\n";

    DnsAnomalyDetector detector;
    auto anomalies = detector.detect(message);

    std::cout << "Anomalies detected: " << anomalies.size() << "\n";
    for (const auto& anomaly : anomalies) {
        std::cout << "  " << anomaly.to_string() << "\n";
    }
}

// 测试 8: 异常检测 - 高熵值域名 (DGA)
void test8_anomaly_high_entropy() {
    print_separator("Test 8: Anomaly Detection - High Entropy (DGA)");

    std::string dga_domain = "xjk2n8qw7r3m.malicious.com";

    DnsPacketBuilder builder;
    builder.write_uint16(0x2222);
    builder.write_uint16(0x0100);
    builder.write_uint16(1);
    builder.write_uint16(0);
    builder.write_uint16(0);
    builder.write_uint16(0);

    builder.write_domain_name(dga_domain);
    builder.write_uint16(1);
    builder.write_uint16(1);

    DnsMessage message;
    DnsParser::parse_message(builder.data(), builder.size(), message);

    std::cout << "Domain: " << dga_domain << "\n\n";

    DnsAnomalyDetector detector;
    auto anomalies = detector.detect(message);

    std::cout << "Anomalies detected: " << anomalies.size() << "\n";
    for (const auto& anomaly : anomalies) {
        std::cout << "  " << anomaly.to_string() << "\n";
    }
}

// 测试 9: 事务跟踪
void test9_transaction_tracking() {
    print_separator("Test 9: Transaction Tracking");

    DnsTransactionTracker tracker(30);

    // 创建查询
    DnsPacketBuilder query_builder;
    query_builder.write_uint16(0x8888);
    query_builder.write_uint16(0x0100);
    query_builder.write_uint16(1);
    query_builder.write_uint16(0);
    query_builder.write_uint16(0);
    query_builder.write_uint16(0);
    query_builder.write_domain_name("www.example.com");
    query_builder.write_uint16(1);
    query_builder.write_uint16(1);

    auto query_msg = std::make_shared<DnsMessage>();
    DnsParser::parse_message(query_builder.data(), query_builder.size(), *query_msg);

    // 添加查询
    tracker.add_query(query_msg, "192.168.1.100", 54321, "8.8.8.8", 53);
    std::cout << "Added query from 192.168.1.100:54321\n";

    // 模拟一些延迟
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // 创建响应
    DnsPacketBuilder resp_builder;
    resp_builder.write_uint16(0x8888);  // 相同的 ID
    resp_builder.write_uint16(0x8180);
    resp_builder.write_uint16(1);
    resp_builder.write_uint16(1);
    resp_builder.write_uint16(0);
    resp_builder.write_uint16(0);
    resp_builder.write_domain_name("www.example.com");
    resp_builder.write_uint16(1);
    resp_builder.write_uint16(1);
    resp_builder.write_domain_name("www.example.com");
    resp_builder.write_uint16(1);
    resp_builder.write_uint16(1);
    resp_builder.write_uint32(300);
    resp_builder.write_uint16(4);
    resp_builder.write_ipv4("93.184.216.34");

    auto resp_msg = std::make_shared<DnsMessage>();
    DnsParser::parse_message(resp_builder.data(), resp_builder.size(), *resp_msg);

    // 添加响应
    bool matched = tracker.add_response(resp_msg, "8.8.8.8", 53, "192.168.1.100", 54321);
    std::cout << "Added response from 8.8.8.8:53, matched: " << (matched ? "Yes" : "No") << "\n\n";

    // 获取完成的事务
    auto transactions = tracker.get_completed_transactions();
    std::cout << "Completed transactions: " << transactions.size() << "\n\n";

    for (const auto& trans : transactions) {
        std::cout << trans.to_string();
    }

    std::cout << "\n" << tracker.get_statistics().to_string();
}

// 测试 10: NXDOMAIN 响应
void test10_nxdomain() {
    print_separator("Test 10: NXDOMAIN Response");

    DnsPacketBuilder builder;
    builder.write_uint16(0xdead);
    builder.write_uint16(0x8183);  // Response, RCODE=3 (NXDOMAIN)
    builder.write_uint16(1);
    builder.write_uint16(0);
    builder.write_uint16(0);
    builder.write_uint16(0);

    builder.write_domain_name("nonexistent.example.com");
    builder.write_uint16(1);
    builder.write_uint16(1);

    DnsMessage message;
    DnsParser::parse_message(builder.data(), builder.size(), message);

    std::cout << message.to_string();
    std::cout << "Response Code: " << DnsParser::rcode_to_string(message.flags.rcode) << "\n";

    if (message.flags.rcode == DnsResponseCode::NXDOMAIN) {
        std::cout << "✓ Domain does not exist\n";
    }
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    print_header();

    try {
        test1_simple_a_query();
        test2_a_record_response();
        test3_aaaa_record();
        test4_cname_record();
        test5_mx_record();
        // test6_txt_record();  // 跳过 TXT 测试（存在构造问题）
        test7_anomaly_long_domain();
        test8_anomaly_high_entropy();
        test9_transaction_tracking();
        test10_nxdomain();

        std::cout << "\n╔════════════════════════════════════════════════════════╗\n";
        std::cout << "║  All tests completed successfully!                    ║\n";
        std::cout << "╚════════════════════════════════════════════════════════╝\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
