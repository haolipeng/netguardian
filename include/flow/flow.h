#ifndef NETGUARDIAN_FLOW_FLOW_H
#define NETGUARDIAN_FLOW_FLOW_H

#include "flow/flow_key.h"
#include "flow/tcp_state_machine.h"
#include "reassembly/tcp_reassembler.h"
#include <chrono>
#include <string>
#include <atomic>
#include <memory>

namespace netguardian {
namespace flow {

// 流方向
enum class FlowDirection {
    UNKNOWN,
    FORWARD,   // 正向（发起方 -> 接收方）
    REVERSE    // 反向（接收方 -> 发起方）
};

// 流统计信息
struct FlowStats {
    // 数据包统计
    uint64_t packet_count;        // 总数据包数
    uint64_t forward_packets;     // 正向数据包数
    uint64_t reverse_packets;     // 反向数据包数

    // 字节统计
    uint64_t byte_count;          // 总字节数
    uint64_t forward_bytes;       // 正向字节数
    uint64_t reverse_bytes;       // 反向字节数

    // 时间统计
    std::chrono::system_clock::time_point first_seen;   // 首次看到的时间
    std::chrono::system_clock::time_point last_seen;    // 最后看到的时间

    FlowStats()
        : packet_count(0)
        , forward_packets(0)
        , reverse_packets(0)
        , byte_count(0)
        , forward_bytes(0)
        , reverse_bytes(0)
        , first_seen(std::chrono::system_clock::now())
        , last_seen(std::chrono::system_clock::now())
    {}

    // 获取流持续时间（秒）
    double duration() const {
        auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(
            last_seen - first_seen
        );
        return diff.count() / 1000.0;
    }

    // 获取平均速率（字节/秒）
    double byte_rate() const {
        double dur = duration();
        return dur > 0 ? byte_count / dur : 0;
    }

    // 获取平均包速率（包/秒）
    double packet_rate() const {
        double dur = duration();
        return dur > 0 ? packet_count / dur : 0;
    }
};

// 流对象
class Flow {
public:
    Flow(const FlowKey& key)
        : key_(key)
        , reverse_key_(key.reverse())
        , stats_()
        , flow_id_(next_flow_id_++)
        , tcp_state_machine_(nullptr)
        , client_reassembler_(nullptr)
        , server_reassembler_(nullptr)
    {
        // 如果是 TCP 流，创建状态机和重组器
        if (key.protocol == 6) {  // TCP
            tcp_state_machine_ = std::unique_ptr<TcpStateMachine>(new TcpStateMachine());
            client_reassembler_ = std::unique_ptr<reassembly::TcpReassembler>(new reassembly::TcpReassembler());
            server_reassembler_ = std::unique_ptr<reassembly::TcpReassembler>(new reassembly::TcpReassembler());
        }
    }

    // 获取流标识
    const FlowKey& key() const { return key_; }
    const FlowKey& reverse_key() const { return reverse_key_; }

    // 获取流 ID
    uint64_t flow_id() const { return flow_id_; }

    // 更新流统计（处理一个数据包）
    void update(uint32_t packet_length, FlowDirection direction) {
        auto now = std::chrono::system_clock::now();

        stats_.packet_count++;
        stats_.byte_count += packet_length;
        stats_.last_seen = now;

        if (direction == FlowDirection::FORWARD) {
            stats_.forward_packets++;
            stats_.forward_bytes += packet_length;
        } else if (direction == FlowDirection::REVERSE) {
            stats_.reverse_packets++;
            stats_.reverse_bytes += packet_length;
        }
    }

    // 获取统计信息
    const FlowStats& stats() const { return stats_; }

    // 判断流是否匹配某个 key（正向或反向）
    bool matches(const FlowKey& key) const {
        return key_ == key || reverse_key_ == key;
    }

    // 判断数据包方向
    FlowDirection get_direction(const FlowKey& packet_key) const {
        if (packet_key == key_) {
            return FlowDirection::FORWARD;
        } else if (packet_key == reverse_key_) {
            return FlowDirection::REVERSE;
        }
        return FlowDirection::UNKNOWN;
    }

    // TCP 相关方法
    bool is_tcp() const { return key_.protocol == 6; }
    bool has_tcp_state() const { return tcp_state_machine_ != nullptr; }

    // 处理 TCP 数据包（更新状态机）
    void process_tcp_packet(const TcpFlags& flags, uint32_t seq, uint32_t ack, bool is_initiator) {
        if (tcp_state_machine_) {
            tcp_state_machine_->process_packet(flags, seq, ack, is_initiator);
        }
    }

    // 获取 TCP 状态
    TcpState get_tcp_state() const {
        return tcp_state_machine_ ? tcp_state_machine_->get_state() : TcpState::UNKNOWN;
    }

    // 获取 TCP 连接信息
    const TcpConnectionInfo* get_tcp_connection_info() const {
        return tcp_state_machine_ ? &tcp_state_machine_->get_connection_info() : nullptr;
    }

    // TCP 重组相关方法
    bool has_tcp_reassembly() const {
        return client_reassembler_ != nullptr && server_reassembler_ != nullptr;
    }

    // 添加 TCP 段到重组器
    // direction: 数据包方向（FORWARD = client->server, REVERSE = server->client）
    bool add_tcp_segment(FlowDirection direction, uint32_t seq,
                        const uint8_t* data, uint16_t len) {
        if (!has_tcp_reassembly() || !data || len == 0) {
            return false;
        }

        if (direction == FlowDirection::FORWARD) {
            // 正向：客户端到服务器
            return client_reassembler_->add_segment(seq, data, len);
        } else if (direction == FlowDirection::REVERSE) {
            // 反向：服务器到客户端
            return server_reassembler_->add_segment(seq, data, len);
        }
        return false;
    }

    // 获取重组后的数据
    std::vector<uint8_t> get_client_reassembled_data(uint32_t& next_seq) {
        if (client_reassembler_) {
            return client_reassembler_->get_reassembled_data(next_seq);
        }
        return std::vector<uint8_t>();
    }

    std::vector<uint8_t> get_server_reassembled_data(uint32_t& next_seq) {
        if (server_reassembler_) {
            return server_reassembler_->get_reassembled_data(next_seq);
        }
        return std::vector<uint8_t>();
    }

    // 检查是否有连续数据可用
    bool has_client_contiguous_data() const {
        return client_reassembler_ && client_reassembler_->has_contiguous_data();
    }

    bool has_server_contiguous_data() const {
        return server_reassembler_ && server_reassembler_->has_contiguous_data();
    }

    // 清除已确认的数据
    void purge_client_acked_data(uint32_t ack_seq) {
        if (client_reassembler_) {
            client_reassembler_->purge_acked_data(ack_seq);
        }
    }

    void purge_server_acked_data(uint32_t ack_seq) {
        if (server_reassembler_) {
            server_reassembler_->purge_acked_data(ack_seq);
        }
    }

    // 获取重组统计信息
    const reassembly::ReassemblyStats* get_client_reassembly_stats() const {
        return client_reassembler_ ? &client_reassembler_->stats() : nullptr;
    }

    const reassembly::ReassemblyStats* get_server_reassembly_stats() const {
        return server_reassembler_ ? &server_reassembler_->stats() : nullptr;
    }

    // 获取流的字符串表示
    std::string to_string() const {
        std::ostringstream oss;
        oss << "Flow #" << flow_id_ << ": " << key_.to_string();
        oss << " | Packets: " << stats_.packet_count
            << " (Fwd: " << stats_.forward_packets
            << ", Rev: " << stats_.reverse_packets << ")";
        oss << " | Bytes: " << stats_.byte_count
            << " (Fwd: " << stats_.forward_bytes
            << ", Rev: " << stats_.reverse_bytes << ")";
        oss << " | Duration: " << std::fixed << std::setprecision(3)
            << stats_.duration() << "s";

        // 添加 TCP 状态信息
        if (tcp_state_machine_) {
            oss << " | TCP State: " << tcp_state_to_string(get_tcp_state());
        }

        return oss.str();
    }

private:
    FlowKey key_;              // 流的五元组标识
    FlowKey reverse_key_;      // 反向流的五元组标识
    FlowStats stats_;          // 流统计信息
    uint64_t flow_id_;         // 流的唯一 ID
    std::unique_ptr<TcpStateMachine> tcp_state_machine_;  // TCP 状态机（仅 TCP 流有效）

    // TCP 重组器（仅 TCP 流有效）
    std::unique_ptr<reassembly::TcpReassembler> client_reassembler_;  // 客户端数据重组器
    std::unique_ptr<reassembly::TcpReassembler> server_reassembler_;  // 服务器数据重组器

    static std::atomic<uint64_t> next_flow_id_;  // 全局流 ID 计数器
};

} // namespace flow
} // namespace netguardian

#endif // NETGUARDIAN_FLOW_FLOW_H
