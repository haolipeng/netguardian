/*
 * IP Fragmentation Reassembly Example
 *
 * 演示 IP 分片重组功能：
 * 1. IPv4 分片重组
 * 2. 乱序分片处理
 * 3. 重叠分片处理
 * 4. 超时管理
 * 5. IPv6 分片重组
 */

#include "reassembly/ipv4_reassembler.h"
#include "reassembly/ipv6_reassembler.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h>
#include <thread>
#include <chrono>

using namespace netguardian::reassembly;

// 打印统计信息
void print_stats(const FragmentStatistics& stats) {
    std::cout << "\n=== Reassembly Statistics ===" << std::endl;
    std::cout << "Total fragments:     " << stats.total_fragments << std::endl;
    std::cout << "Active fragments:    " << stats.active_fragments << std::endl;
    std::cout << "Reassembled packets: " << stats.reassembled_packets << std::endl;
    std::cout << "Timeout count:       " << stats.timeout_count << std::endl;
    std::cout << "Overlap count:       " << stats.overlap_count << std::endl;
    std::cout << "Out-of-order count:  " << stats.out_of_order_count << std::endl;
    std::cout << std::endl;
}

// 打印十六进制数据
void print_hex_data(const std::vector<uint8_t>& data, size_t max_bytes = 64) {
    std::cout << "Data (" << data.size() << " bytes): ";
    size_t print_size = std::min(data.size(), max_bytes);

    for (size_t i = 0; i < print_size; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << " ";
        if ((i + 1) % 16 == 0) {
            std::cout << "\n                    ";
        }
    }

    if (data.size() > max_bytes) {
        std::cout << "... (truncated)";
    }
    std::cout << std::dec << std::endl;
}

// 测试 1：IPv4 顺序分片
void test_ipv4_in_order_fragments() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 1: IPv4 In-Order Fragment Reassembly           ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝\n" << std::endl;

    Ipv4Reassembler reassembler;

    // 创建分片标识
    Ipv4FragmentKey key;
    inet_pton(AF_INET, "192.168.1.100", &key.src_ip);
    inet_pton(AF_INET, "10.0.0.50", &key.dst_ip);
    key.id = 12345;
    key.protocol = 6;  // TCP

    // 模拟一个被分成 3 个分片的数据包
    std::string data = "This is a large IP packet that has been fragmented into multiple pieces for transmission.";

    size_t frag1_len = 30;
    size_t frag2_len = 30;
    size_t frag3_len = data.size() - frag1_len - frag2_len;

    std::cout << "Original data size: " << data.size() << " bytes" << std::endl;
    std::cout << "Splitting into 3 fragments: " << frag1_len << " + " << frag2_len << " + " << frag3_len << " bytes\n" << std::endl;

    // 添加分片 1
    std::cout << "Adding fragment 1 (offset 0, length " << frag1_len << ", MF=1)" << std::endl;
    reassembler.add_fragment(key, 0,
                            reinterpret_cast<const uint8_t*>(data.data()),
                            frag1_len, true);

    // 添加分片 2
    std::cout << "Adding fragment 2 (offset " << frag1_len << ", length " << frag2_len << ", MF=1)" << std::endl;
    reassembler.add_fragment(key, frag1_len,
                            reinterpret_cast<const uint8_t*>(data.data() + frag1_len),
                            frag2_len, true);

    // 添加分片 3（最后一个）
    std::cout << "Adding fragment 3 (offset " << (frag1_len + frag2_len) << ", length " << frag3_len << ", MF=0)" << std::endl;
    reassembler.add_fragment(key, frag1_len + frag2_len,
                            reinterpret_cast<const uint8_t*>(data.data() + frag1_len + frag2_len),
                            frag3_len, false);

    // 检查是否可以重组
    if (reassembler.can_reassemble(key)) {
        std::cout << "\nAll fragments received, reassembling..." << std::endl;
        auto reassembled = reassembler.reassemble(key);

        std::cout << "Reassembled data size: " << reassembled.size() << " bytes" << std::endl;
        std::cout << "Data matches original: "
                  << (std::memcmp(reassembled.data(), data.data(), data.size()) == 0 ? "YES" : "NO")
                  << std::endl;
    }

    print_stats(reassembler.stats());
}

// 测试 2：IPv4 乱序分片
void test_ipv4_out_of_order_fragments() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 2: IPv4 Out-of-Order Fragment Reassembly       ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝\n" << std::endl;

    Ipv4Reassembler reassembler;

    Ipv4FragmentKey key;
    inet_pton(AF_INET, "172.16.0.50", &key.src_ip);
    inet_pton(AF_INET, "192.168.1.10", &key.dst_ip);
    key.id = 54321;
    key.protocol = 17;  // UDP

    std::string data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    size_t frag_size = 12;
    std::cout << "Original data: \"" << data << "\"" << std::endl;
    std::cout << "Fragment size: " << frag_size << " bytes\n" << std::endl;

    // 故意乱序添加分片：3, 1, 2
    std::cout << "Adding fragment 3 (offset 24, out of order)" << std::endl;
    reassembler.add_fragment(key, 24,
                            reinterpret_cast<const uint8_t*>(data.data() + 24),
                            data.size() - 24, false);

    std::cout << "Adding fragment 1 (offset 0, out of order)" << std::endl;
    reassembler.add_fragment(key, 0,
                            reinterpret_cast<const uint8_t*>(data.data()),
                            frag_size, true);

    std::cout << "Adding fragment 2 (offset 12, fills the gap)" << std::endl;
    reassembler.add_fragment(key, 12,
                            reinterpret_cast<const uint8_t*>(data.data() + 12),
                            frag_size, true);

    if (reassembler.can_reassemble(key)) {
        std::cout << "\nReassembling out-of-order fragments..." << std::endl;
        auto reassembled = reassembler.reassemble(key);

        std::cout << "Reassembled: \"" << std::string(reassembled.begin(), reassembled.end()) << "\"" << std::endl;
        std::cout << "Matches original: "
                  << (std::memcmp(reassembled.data(), data.data(), data.size()) == 0 ? "YES" : "NO")
                  << std::endl;
    }

    print_stats(reassembler.stats());
}

// 测试 3：重叠分片
void test_overlapping_fragments() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 3: Overlapping Fragment Handling               ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝\n" << std::endl;

    Ipv4Reassembler reassembler;

    Ipv4FragmentKey key;
    inet_pton(AF_INET, "10.1.1.1", &key.src_ip);
    inet_pton(AF_INET, "10.2.2.2", &key.dst_ip);
    key.id = 99999;
    key.protocol = 6;

    std::cout << "Testing overlapping fragment detection..." << std::endl;

    // 添加第一个分片
    std::string frag1 = "AAAAAAAAAA";
    std::cout << "\nAdding fragment 1: offset 0, data \"" << frag1 << "\"" << std::endl;
    reassembler.add_fragment(key, 0,
                            reinterpret_cast<const uint8_t*>(frag1.data()),
                            frag1.size(), true);

    // 添加重叠的分片（应该被拒绝）
    std::string frag2 = "BBBBBBBBBB";
    std::cout << "Adding fragment 2: offset 5, data \"" << frag2 << "\" (overlaps with fragment 1)" << std::endl;
    reassembler.add_fragment(key, 5,
                            reinterpret_cast<const uint8_t*>(frag2.data()),
                            frag2.size(), true);

    // 添加非重叠的最后分片
    std::string frag3 = "CCCCCCCCCC";
    std::cout << "Adding fragment 3: offset 10, data \"" << frag3 << "\" (no overlap, MF=0)" << std::endl;
    reassembler.add_fragment(key, 10,
                            reinterpret_cast<const uint8_t*>(frag3.data()),
                            frag3.size(), false);

    if (reassembler.can_reassemble(key)) {
        std::cout << "\nReassembling (overlapping fragment was rejected)..." << std::endl;
        auto reassembled = reassembler.reassemble(key);

        std::cout << "Reassembled: \"" << std::string(reassembled.begin(), reassembled.end()) << "\"" << std::endl;
        std::cout << "Expected: \"" << frag1 << frag3 << "\"" << std::endl;
    }

    print_stats(reassembler.stats());
}

// 测试 4：超时管理
void test_timeout() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 4: Fragment Timeout Management                 ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝\n" << std::endl;

    // 使用 2 秒超时
    Ipv4Reassembler reassembler(2);

    Ipv4FragmentKey key;
    inet_pton(AF_INET, "192.168.100.1", &key.src_ip);
    inet_pton(AF_INET, "192.168.100.2", &key.dst_ip);
    key.id = 11111;
    key.protocol = 6;

    std::string data = "Incomplete fragment set";

    std::cout << "Adding incomplete fragment set (missing last fragment)..." << std::endl;
    reassembler.add_fragment(key, 0,
                            reinterpret_cast<const uint8_t*>(data.data()),
                            data.size(), true);

    std::cout << "Waiting 3 seconds for timeout..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(3));

    std::cout << "Cleaning up timed-out fragments..." << std::endl;
    reassembler.cleanup_timeout();

    std::cout << "Can reassemble after timeout: "
              << (reassembler.can_reassemble(key) ? "YES" : "NO") << std::endl;

    print_stats(reassembler.stats());
}

// 测试 5：IPv6 分片重组
void test_ipv6_reassembly() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 5: IPv6 Fragment Reassembly                    ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝\n" << std::endl;

    Ipv6Reassembler reassembler;

    Ipv6FragmentKey key;
    // 简化：使用部分填充的 IPv6 地址
    std::memset(key.src_ip.data(), 0, 16);
    std::memset(key.dst_ip.data(), 0, 16);
    key.src_ip[15] = 1;  // ::1
    key.dst_ip[15] = 2;  // ::2
    key.id = 77777;

    std::string data = "IPv6 fragmented packet data for testing reassembly functionality.";

    size_t frag1_len = 25;
    size_t frag2_len = data.size() - frag1_len;

    std::cout << "IPv6 packet size: " << data.size() << " bytes" << std::endl;
    std::cout << "Splitting into 2 fragments: " << frag1_len << " + " << frag2_len << " bytes\n" << std::endl;

    std::cout << "Adding IPv6 fragment 1..." << std::endl;
    reassembler.add_fragment(key, 0,
                            reinterpret_cast<const uint8_t*>(data.data()),
                            frag1_len, true);

    std::cout << "Adding IPv6 fragment 2..." << std::endl;
    reassembler.add_fragment(key, frag1_len,
                            reinterpret_cast<const uint8_t*>(data.data() + frag1_len),
                            frag2_len, false);

    if (reassembler.can_reassemble(key)) {
        std::cout << "\nReassembling IPv6 fragments..." << std::endl;
        auto reassembled = reassembler.reassemble(key);

        std::cout << "Reassembled: \"" << std::string(reassembled.begin(), reassembled.end()) << "\"" << std::endl;
        std::cout << "Matches original: "
                  << (std::memcmp(reassembled.data(), data.data(), data.size()) == 0 ? "YES" : "NO")
                  << std::endl;
    }

    print_stats(reassembler.stats());
}

int main() {
    std::cout << "\n╔════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║       NetGuardian IP Reassembly Demo                  ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════╝" << std::endl;

    try {
        // 运行所有测试
        test_ipv4_in_order_fragments();
        test_ipv4_out_of_order_fragments();
        test_overlapping_fragments();
        test_timeout();
        test_ipv6_reassembly();

        std::cout << "\n╔════════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║  All tests completed successfully!                    ║" << std::endl;
        std::cout << "╚════════════════════════════════════════════════════════╝\n" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
