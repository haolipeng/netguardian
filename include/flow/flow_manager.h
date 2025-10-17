#ifndef NETGUARDIAN_FLOW_FLOW_MANAGER_H
#define NETGUARDIAN_FLOW_FLOW_MANAGER_H

#include "flow/flow_table.h"
#include <chrono>
#include <vector>
#include <functional>

namespace netguardian {
namespace flow {

// 流超时配置
struct FlowTimeoutConfig {
    // TCP 流超时（秒）
    uint32_t tcp_established_timeout;  // 已建立连接的超时
    uint32_t tcp_closing_timeout;      // 正在关闭连接的超时
    uint32_t tcp_closed_timeout;       // 已关闭连接的超时
    uint32_t tcp_unknown_timeout;      // 未知状态连接的超时

    // UDP 流超时（秒）
    uint32_t udp_timeout;              // UDP 流超时

    // 其他协议超时（秒）
    uint32_t other_timeout;            // 其他协议流超时

    // 默认配置
    FlowTimeoutConfig()
        : tcp_established_timeout(3600)    // 1小时
        , tcp_closing_timeout(120)         // 2分钟
        , tcp_closed_timeout(10)           // 10秒
        , tcp_unknown_timeout(300)         // 5分钟
        , udp_timeout(60)                  // 1分钟
        , other_timeout(60)                // 1分钟
    {}
};

// 流导出回调函数类型
// 参数：流对象
using FlowExportCallback = std::function<void(const Flow&)>;

// 流管理器
class FlowManager {
public:
    explicit FlowManager(FlowTable& flow_table, const FlowTimeoutConfig& config = FlowTimeoutConfig())
        : flow_table_(flow_table)
        , config_(config)
        , last_cleanup_time_(std::chrono::system_clock::now())
    {}

    // 设置流导出回调
    void set_export_callback(FlowExportCallback callback) {
        export_callback_ = callback;
    }

    // 检查并清理超时的流
    // 返回：被清理的流数量
    size_t cleanup_expired_flows();

    // 强制导出所有活跃流
    void export_all_flows();

    // 获取超时配置
    const FlowTimeoutConfig& get_config() const { return config_; }

    // 设置超时配置
    void set_config(const FlowTimeoutConfig& config) { config_ = config; }

    // 获取上次清理时间
    std::chrono::system_clock::time_point get_last_cleanup_time() const {
        return last_cleanup_time_;
    }

private:
    FlowTable& flow_table_;                // 流表引用
    FlowTimeoutConfig config_;             // 超时配置
    FlowExportCallback export_callback_;   // 导出回调
    std::chrono::system_clock::time_point last_cleanup_time_;  // 上次清理时间

    // 判断流是否超时
    bool is_flow_expired(const Flow& flow, std::chrono::system_clock::time_point now) const;

    // 获取流的超时时间（秒）
    uint32_t get_flow_timeout(const Flow& flow) const;

    // 导出单个流
    void export_flow(const Flow& flow);
};

} // namespace flow
} // namespace netguardian

#endif // NETGUARDIAN_FLOW_FLOW_MANAGER_H
