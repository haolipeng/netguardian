#ifndef NETGUARDIAN_FLOW_TCP_STATE_MACHINE_H
#define NETGUARDIAN_FLOW_TCP_STATE_MACHINE_H

#include "flow/tcp_state.h"
#include "decoders/protocol_headers.h"
#include <memory>

namespace netguardian {
namespace flow {

// TCP 数据包标志位提取
struct TcpFlags {
    bool syn;
    bool ack;
    bool fin;
    bool rst;
    bool psh;
    bool urg;

    TcpFlags()
        : syn(false), ack(false), fin(false)
        , rst(false), psh(false), urg(false)
    {}

    // 从 TCP 头部提取标志位
    static TcpFlags from_header(const decoders::TcpHeader* hdr) {
        TcpFlags flags;
        flags.syn = (hdr->flags & TCP_FLAG_SYN) != 0;
        flags.ack = (hdr->flags & TCP_FLAG_ACK) != 0;
        flags.fin = (hdr->flags & TCP_FLAG_FIN) != 0;
        flags.rst = (hdr->flags & TCP_FLAG_RST) != 0;
        flags.psh = (hdr->flags & TCP_FLAG_PSH) != 0;
        flags.urg = (hdr->flags & TCP_FLAG_URG) != 0;
        return flags;
    }

    // 判断数据包类型
    bool is_syn() const { return syn && !ack; }
    bool is_syn_ack() const { return syn && ack; }
    bool is_ack() const { return ack && !syn && !fin; }
    bool is_fin() const { return fin; }
    bool is_fin_ack() const { return fin && ack; }
    bool is_rst() const { return rst; }
};

// TCP 状态机
class TcpStateMachine {
public:
    TcpStateMachine() : conn_info_() {}

    // 处理 TCP 数据包，更新状态
    // is_initiator: 是否是发起方的数据包
    void process_packet(const TcpFlags& flags, uint32_t seq, uint32_t ack, bool is_initiator);

    // 获取当前状态
    TcpState get_state() const { return conn_info_.state; }

    // 获取连接信息
    const TcpConnectionInfo& get_connection_info() const { return conn_info_; }

    // 状态转换（根据事件）
    void transition(TcpEvent event, bool is_initiator);

    // 检测异常
    void detect_anomalies(uint32_t seq, uint32_t expected_seq, bool is_initiator);

private:
    TcpConnectionInfo conn_info_;

    // 状态转换辅助函数
    void handle_syn(bool is_initiator);
    void handle_syn_ack(bool is_initiator);
    void handle_ack(bool is_initiator);
    void handle_fin(bool is_initiator);
    void handle_rst(bool is_initiator);
};

} // namespace flow
} // namespace netguardian

#endif // NETGUARDIAN_FLOW_TCP_STATE_MACHINE_H
