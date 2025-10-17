/*
 * TCP Reassembly Example
 *
 * 演示 TCP 流重组功能：
 * 1. 顺序段处理
 * 2. 乱序段处理
 * 3. 重叠检测
 * 4. 数据空洞检测
 * 5. 数据重组
 */

#include "reassembly/tcp_reassembler.h"
#include "flow/flow.h"
#include "flow/flow_key.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h>

using namespace netguardian;
using namespace netguardian::reassembly;
using namespace netguardian::flow;

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

// 打印 ASCII 数据
void print_ascii_data(const std::vector<uint8_t>& data) {
    std::cout << "ASCII Data: \"";
    for (uint8_t byte : data) {
        if (byte >= 32 && byte < 127) {
            std::cout << static_cast<char>(byte);
        } else {
            std::cout << '.';
        }
    }
    std::cout << "\"" << std::endl;
}

// 打印统计信息
void print_stats(const ReassemblyStats& stats) {
    std::cout << "\n=== Reassembly Statistics ===" << std::endl;
    std::cout << "Total segments:     " << stats.total_segments << std::endl;
    std::cout << "Active segments:    " << stats.active_segments << std::endl;
    std::cout << "Total bytes:        " << stats.total_bytes << std::endl;
    std::cout << "Reassembled bytes:  " << stats.reassembled_bytes << std::endl;
    std::cout << "Overlap count:      " << stats.overlap_count << std::endl;
    std::cout << "Out-of-order count: " << stats.out_of_order_count << std::endl;
    std::cout << "Gap count:          " << stats.gap_count << std::endl;
    std::cout << std::endl;
}

// 测试 1：顺序段处理
void test_in_order_segments() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 1: In-Order Segment Processing                 ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝\n" << std::endl;

    TcpReassembler reassembler;

    // 模拟 HTTP GET 请求，分成多个段
    std::string request = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    uint32_t seq = 1000;

    std::cout << "Adding segments in order..." << std::endl;

    // 分成 3 个段
    size_t seg1_len = 10;
    size_t seg2_len = 20;
    size_t seg3_len = request.size() - seg1_len - seg2_len;

    reassembler.add_segment(seq,
                           reinterpret_cast<const uint8_t*>(request.data()),
                           seg1_len);
    std::cout << "Segment 1: seq=" << seq << ", len=" << seg1_len << std::endl;

    reassembler.add_segment(seq + seg1_len,
                           reinterpret_cast<const uint8_t*>(request.data() + seg1_len),
                           seg2_len);
    std::cout << "Segment 2: seq=" << (seq + seg1_len) << ", len=" << seg2_len << std::endl;

    reassembler.add_segment(seq + seg1_len + seg2_len,
                           reinterpret_cast<const uint8_t*>(request.data() + seg1_len + seg2_len),
                           seg3_len);
    std::cout << "Segment 3: seq=" << (seq + seg1_len + seg2_len) << ", len=" << seg3_len << std::endl;

    // 获取重组后的数据
    uint32_t next_seq;
    auto data = reassembler.get_reassembled_data(next_seq);

    std::cout << "\nReassembled data:" << std::endl;
    print_ascii_data(data);
    std::cout << "Next expected seq: " << next_seq << std::endl;

    print_stats(reassembler.stats());
}

// 测试 2：乱序段处理
void test_out_of_order_segments() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 2: Out-of-Order Segment Processing             ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝\n" << std::endl;

    TcpReassembler reassembler;

    std::string data_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint32_t seq = 2000;

    std::cout << "Adding segments out of order..." << std::endl;

    // 先添加第 3 个段
    reassembler.add_segment(seq + 20,
                           reinterpret_cast<const uint8_t*>(data_str.data() + 20),
                           6);
    std::cout << "Added segment 3: seq=" << (seq + 20) << ", data=\""
              << data_str.substr(20, 6) << "\"" << std::endl;

    // 再添加第 1 个段
    reassembler.add_segment(seq,
                           reinterpret_cast<const uint8_t*>(data_str.data()),
                           10);
    std::cout << "Added segment 1: seq=" << seq << ", data=\""
              << data_str.substr(0, 10) << "\"" << std::endl;

    // 最后添加第 2 个段（填补空洞）
    reassembler.add_segment(seq + 10,
                           reinterpret_cast<const uint8_t*>(data_str.data() + 10),
                           10);
    std::cout << "Added segment 2: seq=" << (seq + 10) << ", data=\""
              << data_str.substr(10, 10) << "\"" << std::endl;

    // 获取重组后的数据
    uint32_t next_seq;
    auto data = reassembler.get_reassembled_data(next_seq);

    std::cout << "\nReassembled data:" << std::endl;
    print_ascii_data(data);
    std::cout << "Next expected seq: " << next_seq << std::endl;

    print_stats(reassembler.stats());
}

// 测试 3：重叠段处理
void test_overlapping_segments() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 3: Overlapping Segment Processing              ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝\n" << std::endl;

    TcpReassembler reassembler(OverlapPolicy::FIRST);

    uint32_t seq = 3000;

    std::cout << "Adding overlapping segments (FIRST policy)..." << std::endl;

    // 第 1 个段
    std::string seg1 = "AAAAAAAAAA";
    reassembler.add_segment(seq,
                           reinterpret_cast<const uint8_t*>(seg1.data()),
                           seg1.size());
    std::cout << "Segment 1: seq=" << seq << ", data=\"" << seg1 << "\"" << std::endl;

    // 第 2 个段（与第 1 个段有部分重叠）
    std::string seg2 = "BBBBBBBBBB";
    reassembler.add_segment(seq + 5,
                           reinterpret_cast<const uint8_t*>(seg2.data()),
                           seg2.size());
    std::cout << "Segment 2: seq=" << (seq + 5) << ", data=\"" << seg2
              << "\" (overlaps with segment 1)" << std::endl;

    // 第 3 个段（完全被包含）
    std::string seg3 = "CCCC";
    reassembler.add_segment(seq + 2,
                           reinterpret_cast<const uint8_t*>(seg3.data()),
                           seg3.size());
    std::cout << "Segment 3: seq=" << (seq + 2) << ", data=\"" << seg3
              << "\" (completely overlapped)" << std::endl;

    // 获取重组后的数据
    uint32_t next_seq;
    auto data = reassembler.get_reassembled_data(next_seq);

    std::cout << "\nReassembled data (FIRST policy keeps earlier data):" << std::endl;
    print_ascii_data(data);
    std::cout << "Next expected seq: " << next_seq << std::endl;

    print_stats(reassembler.stats());
}

// 测试 4：数据空洞检测
void test_gap_detection() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 4: Gap Detection                               ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝\n" << std::endl;

    TcpReassembler reassembler;

    uint32_t seq = 4000;

    std::cout << "Adding segments with gaps..." << std::endl;

    // 第 1 个段
    std::string seg1 = "AAAAAAAAAA";
    reassembler.add_segment(seq,
                           reinterpret_cast<const uint8_t*>(seg1.data()),
                           seg1.size());
    std::cout << "Segment 1: seq=" << seq << ", data=\"" << seg1 << "\"" << std::endl;

    // 第 2 个段（中间有空洞）
    std::string seg2 = "CCCCCCCCCC";
    reassembler.add_segment(seq + 20,
                           reinterpret_cast<const uint8_t*>(seg2.data()),
                           seg2.size());
    std::cout << "Segment 2: seq=" << (seq + 20) << ", data=\"" << seg2
              << "\" (gap between seg1 and seg2)" << std::endl;

    // 获取重组后的数据（应该只返回第 1 个段）
    uint32_t next_seq;
    auto data = reassembler.get_reassembled_data(next_seq);

    std::cout << "\nReassembled data (stops at gap):" << std::endl;
    print_ascii_data(data);
    std::cout << "Next expected seq: " << next_seq << std::endl;
    std::cout << "Has contiguous data: " << (reassembler.has_contiguous_data() ? "Yes" : "No") << std::endl;

    // 填补空洞
    std::string gap_seg = "BBBBBBBBBB";
    reassembler.add_segment(seq + 10,
                           reinterpret_cast<const uint8_t*>(gap_seg.data()),
                           gap_seg.size());
    std::cout << "\nFilling the gap: seq=" << (seq + 10) << ", data=\"" << gap_seg << "\"" << std::endl;

    // 再次获取数据
    data = reassembler.get_reassembled_data(next_seq);
    std::cout << "\nReassembled data (after filling gap):" << std::endl;
    print_ascii_data(data);
    std::cout << "Next expected seq: " << next_seq << std::endl;

    print_stats(reassembler.stats());
}

// 测试 5：Flow 集成测试
void test_flow_integration() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 5: Flow Integration                            ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝\n" << std::endl;

    // 创建 TCP 流
    FlowKey key;
    key.src_ip = htonl(0xC0A80101);  // 192.168.1.1
    key.dst_ip = htonl(0xC0A80102);  // 192.168.1.2
    key.src_port = 12345;
    key.dst_port = 80;
    key.protocol = 6;  // TCP

    Flow flow(key);

    std::cout << "Created flow: " << flow.key().to_string() << std::endl;
    std::cout << "Has TCP reassembly: " << (flow.has_tcp_reassembly() ? "Yes" : "No") << std::endl;

    // 模拟客户端到服务器的 HTTP 请求
    std::string client_data = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
    uint32_t client_seq = 1000;

    std::cout << "\nClient -> Server:" << std::endl;
    flow.add_tcp_segment(FlowDirection::FORWARD, client_seq,
                        reinterpret_cast<const uint8_t*>(client_data.data()),
                        client_data.size());
    std::cout << "Added " << client_data.size() << " bytes, seq=" << client_seq << std::endl;

    uint32_t next_seq;
    auto data = flow.get_client_reassembled_data(next_seq);
    std::cout << "Reassembled client data:" << std::endl;
    print_ascii_data(data);

    // 模拟服务器到客户端的 HTTP 响应
    std::string server_data = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
    uint32_t server_seq = 2000;

    std::cout << "\nServer -> Client:" << std::endl;
    flow.add_tcp_segment(FlowDirection::REVERSE, server_seq,
                        reinterpret_cast<const uint8_t*>(server_data.data()),
                        server_data.size());
    std::cout << "Added " << server_data.size() << " bytes, seq=" << server_seq << std::endl;

    data = flow.get_server_reassembled_data(next_seq);
    std::cout << "Reassembled server data:" << std::endl;
    print_ascii_data(data);

    // 打印统计信息
    auto client_stats = flow.get_client_reassembly_stats();
    auto server_stats = flow.get_server_reassembly_stats();

    std::cout << "\nClient Reassembly Stats:" << std::endl;
    if (client_stats) {
        std::cout << "  Total segments: " << client_stats->total_segments << std::endl;
        std::cout << "  Total bytes: " << client_stats->total_bytes << std::endl;
        std::cout << "  Reassembled bytes: " << client_stats->reassembled_bytes << std::endl;
    }

    std::cout << "\nServer Reassembly Stats:" << std::endl;
    if (server_stats) {
        std::cout << "  Total segments: " << server_stats->total_segments << std::endl;
        std::cout << "  Total bytes: " << server_stats->total_bytes << std::endl;
        std::cout << "  Reassembled bytes: " << server_stats->reassembled_bytes << std::endl;
    }
}

int main() {
    std::cout << "\n╔════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║       NetGuardian TCP Reassembly Demo                 ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════╝" << std::endl;

    try {
        // 运行所有测试
        test_in_order_segments();
        test_out_of_order_segments();
        test_overlapping_segments();
        test_gap_detection();
        test_flow_integration();

        std::cout << "\n╔════════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║  All tests completed successfully!                    ║" << std::endl;
        std::cout << "╚════════════════════════════════════════════════════════╝\n" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
