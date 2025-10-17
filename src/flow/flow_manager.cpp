#include "flow/flow_manager.h"
#include <algorithm>

namespace netguardian {
namespace flow {

size_t FlowManager::cleanup_expired_flows() {
    auto now = std::chrono::system_clock::now();
    size_t removed_count = 0;

    // 获取所有流
    auto all_flows = flow_table_.get_all_flows();

    // 检查每个流是否超时
    std::vector<FlowKey> expired_keys;
    for (const auto& flow : all_flows) {
        if (is_flow_expired(*flow, now)) {
            // 导出流（如果设置了回调）
            export_flow(*flow);
            expired_keys.push_back(flow->key());
        }
    }

    // 从流表中删除超时的流
    for (const auto& key : expired_keys) {
        flow_table_.remove_flow(key);
        removed_count++;
    }

    last_cleanup_time_ = now;
    return removed_count;
}

void FlowManager::export_all_flows() {
    if (!export_callback_) {
        return;
    }

    // 获取所有流并导出
    auto all_flows = flow_table_.get_all_flows();
    for (const auto& flow : all_flows) {
        export_flow(*flow);
    }
}

bool FlowManager::is_flow_expired(const Flow& flow, std::chrono::system_clock::time_point now) const {
    const auto& stats = flow.stats();

    // 计算流的空闲时间（秒）
    auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
        now - stats.last_seen
    ).count();

    // 获取该流的超时时间
    uint32_t timeout = get_flow_timeout(flow);

    return idle_time >= timeout;
}

uint32_t FlowManager::get_flow_timeout(const Flow& flow) const {
    // TCP 流
    if (flow.is_tcp() && flow.has_tcp_state()) {
        const auto* conn_info = flow.get_tcp_connection_info();
        if (conn_info) {
            // 根据 TCP 状态确定超时时间
            if (conn_info->is_closed()) {
                return config_.tcp_closed_timeout;
            } else if (conn_info->is_closing()) {
                return config_.tcp_closing_timeout;
            } else if (conn_info->is_established()) {
                return config_.tcp_established_timeout;
            } else {
                return config_.tcp_unknown_timeout;
            }
        }
    }

    // UDP 流
    if (flow.key().protocol == 17) {  // UDP
        return config_.udp_timeout;
    }

    // 其他协议
    return config_.other_timeout;
}

void FlowManager::export_flow(const Flow& flow) {
    if (export_callback_) {
        export_callback_(flow);
    }
}

} // namespace flow
} // namespace netguardian
