#ifndef NETGUARDIAN_FLOW_TCP_STATE_H
#define NETGUARDIAN_FLOW_TCP_STATE_H

#include <string>
#include <cstdint>

namespace netguardian {
namespace flow {

// TCP 连接状态（基于 TCP 状态机）
enum class TcpState {
    CLOSED,           // 初始状态/连接已关闭
    LISTEN,           // 服务器监听状态（被动打开）
    SYN_SENT,         // 客户端发送 SYN 后（主动打开）
    SYN_RECEIVED,     // 服务器收到 SYN 并发送 SYN-ACK
    ESTABLISHED,      // 连接已建立
    FIN_WAIT_1,       // 主动关闭方发送 FIN
    FIN_WAIT_2,       // 主动关闭方收到对方 ACK
    CLOSE_WAIT,       // 被动关闭方收到 FIN
    CLOSING,          // 双方同时关闭
    LAST_ACK,         // 被动关闭方发送 FIN
    TIME_WAIT,        // 主动关闭方收到 FIN 后等待
    UNKNOWN           // 未知状态（中途捕获的流）
};

// TCP 状态转换为字符串
inline std::string tcp_state_to_string(TcpState state) {
    switch (state) {
        case TcpState::CLOSED:        return "CLOSED";
        case TcpState::LISTEN:        return "LISTEN";
        case TcpState::SYN_SENT:      return "SYN_SENT";
        case TcpState::SYN_RECEIVED:  return "SYN_RECEIVED";
        case TcpState::ESTABLISHED:   return "ESTABLISHED";
        case TcpState::FIN_WAIT_1:    return "FIN_WAIT_1";
        case TcpState::FIN_WAIT_2:    return "FIN_WAIT_2";
        case TcpState::CLOSE_WAIT:    return "CLOSE_WAIT";
        case TcpState::CLOSING:       return "CLOSING";
        case TcpState::LAST_ACK:      return "LAST_ACK";
        case TcpState::TIME_WAIT:     return "TIME_WAIT";
        case TcpState::UNKNOWN:       return "UNKNOWN";
        default:                      return "INVALID";
    }
}

// TCP 事件（用于状态转换）
enum class TcpEvent {
    SYN,              // 收到 SYN
    SYN_ACK,          // 收到 SYN-ACK
    ACK,              // 收到 ACK
    FIN,              // 收到 FIN
    FIN_ACK,          // 收到 FIN-ACK
    RST,              // 收到 RST
    DATA,             // 收到数据包
    TIMEOUT           // 超时
};

// TCP 连接信息
struct TcpConnectionInfo {
    TcpState state;                  // 当前状态

    // 握手信息
    bool syn_seen;                   // 是否看到 SYN
    bool syn_ack_seen;               // 是否看到 SYN-ACK
    bool handshake_complete;         // 三次握手是否完成

    // 挥手信息
    bool fin_from_initiator;         // 发起方是否发送 FIN
    bool fin_from_responder;         // 响应方是否发送 FIN
    bool shutdown_complete;          // 连接关闭是否完成

    // 异常检测
    bool rst_seen;                   // 是否看到 RST
    uint32_t retransmissions;        // 重传次数
    uint32_t out_of_order;           // 乱序包数量

    // 序列号追踪（用于检测重传和乱序）
    uint32_t initiator_seq;          // 发起方序列号
    uint32_t responder_seq;          // 响应方序列号
    uint32_t initiator_ack;          // 发起方确认号
    uint32_t responder_ack;          // 响应方确认号

    TcpConnectionInfo()
        : state(TcpState::UNKNOWN)
        , syn_seen(false)
        , syn_ack_seen(false)
        , handshake_complete(false)
        , fin_from_initiator(false)
        , fin_from_responder(false)
        , shutdown_complete(false)
        , rst_seen(false)
        , retransmissions(0)
        , out_of_order(0)
        , initiator_seq(0)
        , responder_seq(0)
        , initiator_ack(0)
        , responder_ack(0)
    {}

    // 检查连接是否已完全建立
    bool is_established() const {
        return state == TcpState::ESTABLISHED;
    }

    // 检查连接是否正在关闭
    bool is_closing() const {
        return state == TcpState::FIN_WAIT_1 ||
               state == TcpState::FIN_WAIT_2 ||
               state == TcpState::CLOSE_WAIT ||
               state == TcpState::CLOSING ||
               state == TcpState::LAST_ACK ||
               state == TcpState::TIME_WAIT;
    }

    // 检查连接是否已关闭
    bool is_closed() const {
        return state == TcpState::CLOSED || shutdown_complete;
    }

    // 检查连接是否异常
    bool is_abnormal() const {
        return rst_seen || retransmissions > 10 || out_of_order > 10;
    }
};

} // namespace flow
} // namespace netguardian

#endif // NETGUARDIAN_FLOW_TCP_STATE_H
