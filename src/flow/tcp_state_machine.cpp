#include "flow/tcp_state_machine.h"

namespace netguardian {
namespace flow {

void TcpStateMachine::process_packet(const TcpFlags& flags, uint32_t seq, uint32_t ack, bool is_initiator) {
    // 处理 RST（优先级最高）
    if (flags.is_rst()) {
        handle_rst(is_initiator);
        return;
    }

    // 处理 SYN
    if (flags.is_syn() && !flags.ack) {
        handle_syn(is_initiator);
        if (is_initiator) {
            conn_info_.initiator_seq = seq;
        }
        return;
    }

    // 处理 SYN-ACK
    if (flags.is_syn_ack()) {
        handle_syn_ack(is_initiator);
        if (!is_initiator) {
            conn_info_.responder_seq = seq;
            conn_info_.responder_ack = ack;
        }
        return;
    }

    // 处理 FIN
    if (flags.is_fin()) {
        handle_fin(is_initiator);
        return;
    }

    // 处理普通 ACK
    if (flags.is_ack()) {
        handle_ack(is_initiator);

        // 更新序列号和确认号
        if (is_initiator) {
            conn_info_.initiator_ack = ack;
        } else {
            conn_info_.responder_ack = ack;
        }
    }

    // 检测重传和乱序（简化版）
    if (is_initiator && conn_info_.initiator_seq > 0) {
        if (seq < conn_info_.initiator_seq) {
            conn_info_.retransmissions++;
        } else if (seq > conn_info_.initiator_seq + 1460) {  // 假设 MTU 1460
            conn_info_.out_of_order++;
        }
        conn_info_.initiator_seq = seq;
    } else if (!is_initiator && conn_info_.responder_seq > 0) {
        if (seq < conn_info_.responder_seq) {
            conn_info_.retransmissions++;
        } else if (seq > conn_info_.responder_seq + 1460) {
            conn_info_.out_of_order++;
        }
        conn_info_.responder_seq = seq;
    }
}

void TcpStateMachine::handle_syn(bool is_initiator) {
    if (conn_info_.state == TcpState::UNKNOWN || conn_info_.state == TcpState::CLOSED) {
        conn_info_.syn_seen = true;
        conn_info_.state = TcpState::SYN_SENT;
    }
}

void TcpStateMachine::handle_syn_ack(bool is_initiator) {
    if (conn_info_.state == TcpState::SYN_SENT) {
        conn_info_.syn_ack_seen = true;
        conn_info_.state = TcpState::SYN_RECEIVED;
    }
}

void TcpStateMachine::handle_ack(bool is_initiator) {
    // 完成三次握手
    if (conn_info_.state == TcpState::SYN_RECEIVED && is_initiator) {
        conn_info_.handshake_complete = true;
        conn_info_.state = TcpState::ESTABLISHED;
        return;
    }

    // FIN-WAIT-1 -> FIN-WAIT-2
    if (conn_info_.state == TcpState::FIN_WAIT_1) {
        conn_info_.state = TcpState::FIN_WAIT_2;
        return;
    }

    // CLOSING -> TIME-WAIT
    if (conn_info_.state == TcpState::CLOSING) {
        conn_info_.state = TcpState::TIME_WAIT;
        return;
    }

    // LAST-ACK -> CLOSED
    if (conn_info_.state == TcpState::LAST_ACK) {
        conn_info_.state = TcpState::CLOSED;
        conn_info_.shutdown_complete = true;
        return;
    }
}

void TcpStateMachine::handle_fin(bool is_initiator) {
    // 记录哪一方发送了 FIN
    if (is_initiator) {
        conn_info_.fin_from_initiator = true;
    } else {
        conn_info_.fin_from_responder = true;
    }

    // 状态转换
    if (conn_info_.state == TcpState::ESTABLISHED) {
        if (is_initiator) {
            conn_info_.state = TcpState::FIN_WAIT_1;
        } else {
            conn_info_.state = TcpState::CLOSE_WAIT;
        }
        return;
    }

    // FIN-WAIT-2 -> TIME-WAIT
    if (conn_info_.state == TcpState::FIN_WAIT_2 && !is_initiator) {
        conn_info_.state = TcpState::TIME_WAIT;
        return;
    }

    // CLOSE-WAIT -> LAST-ACK
    if (conn_info_.state == TcpState::CLOSE_WAIT && !is_initiator) {
        conn_info_.state = TcpState::LAST_ACK;
        return;
    }

    // 双方同时关闭
    if (conn_info_.state == TcpState::FIN_WAIT_1 && !is_initiator) {
        conn_info_.state = TcpState::CLOSING;
        return;
    }

    // 检查是否完全关闭
    if (conn_info_.fin_from_initiator && conn_info_.fin_from_responder) {
        conn_info_.shutdown_complete = true;
    }
}

void TcpStateMachine::handle_rst(bool is_initiator) {
    conn_info_.rst_seen = true;
    conn_info_.state = TcpState::CLOSED;
    conn_info_.shutdown_complete = true;
}

void TcpStateMachine::transition(TcpEvent event, bool is_initiator) {
    switch (event) {
        case TcpEvent::SYN:
            handle_syn(is_initiator);
            break;
        case TcpEvent::SYN_ACK:
            handle_syn_ack(is_initiator);
            break;
        case TcpEvent::ACK:
            handle_ack(is_initiator);
            break;
        case TcpEvent::FIN:
        case TcpEvent::FIN_ACK:
            handle_fin(is_initiator);
            break;
        case TcpEvent::RST:
            handle_rst(is_initiator);
            break;
        default:
            break;
    }
}

void TcpStateMachine::detect_anomalies(uint32_t seq, uint32_t expected_seq, bool is_initiator) {
    // 检测重传
    if (seq < expected_seq) {
        conn_info_.retransmissions++;
    }

    // 检测乱序
    if (seq > expected_seq + 1460) {  // 假设最大段大小为 1460
        conn_info_.out_of_order++;
    }
}

} // namespace flow
} // namespace netguardian
