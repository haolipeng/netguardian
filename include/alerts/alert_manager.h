#ifndef NETGUARDIAN_ALERTS_ALERT_MANAGER_H
#define NETGUARDIAN_ALERTS_ALERT_MANAGER_H

#include "alerts/alert.h"
#include "alerts/alert_generator.h"
#include "alerts/alert_output.h"
#include <memory>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <algorithm>

namespace netguardian {
namespace alerts {

// 告警统计信息
struct AlertStatistics {
    uint64_t total_alerts;          // 总告警数
    uint64_t suppressed_alerts;     // 被抑制的告警数
    uint64_t critical_alerts;       // 严重告警数
    uint64_t high_alerts;           // 高优先级告警数
    uint64_t medium_alerts;         // 中等优先级告警数
    uint64_t low_alerts;            // 低优先级告警数

    AlertStatistics()
        : total_alerts(0)
        , suppressed_alerts(0)
        , critical_alerts(0)
        , high_alerts(0)
        , medium_alerts(0)
        , low_alerts(0)
    {}

    std::string to_string() const {
        std::ostringstream oss;
        oss << "Total Alerts: " << total_alerts << "\n";
        oss << "  Critical: " << critical_alerts << "\n";
        oss << "  High:     " << high_alerts << "\n";
        oss << "  Medium:   " << medium_alerts << "\n";
        oss << "  Low:      " << low_alerts << "\n";
        oss << "Suppressed: " << suppressed_alerts;
        return oss.str();
    }
};

// 告警去重配置
struct DeduplicationConfig {
    bool enabled;                   // 是否启用去重
    uint32_t time_window_seconds;   // 时间窗口（秒）
    uint32_t max_alerts_per_rule;   // 每条规则在时间窗口内的最大告警数

    DeduplicationConfig()
        : enabled(true)
        , time_window_seconds(60)
        , max_alerts_per_rule(10)
    {}
};

// 告警管理器
class AlertManager {
public:
    AlertManager()
        : generator_()
        , dedup_config_()
    {}

    // 添加输出器
    void add_output(std::shared_ptr<AlertOutput> output) {
        std::lock_guard<std::mutex> lock(mutex_);
        outputs_.push_back(output);
    }

    // 设置去重配置
    void set_deduplication_config(const DeduplicationConfig& config) {
        std::lock_guard<std::mutex> lock(mutex_);
        dedup_config_ = config;
    }

    // 处理告警
    void process_alert(std::shared_ptr<Alert> alert) {
        std::lock_guard<std::mutex> lock(mutex_);

        // 统计
        stats_.total_alerts++;
        update_priority_stats(alert->priority);

        // 去重检查
        if (dedup_config_.enabled && should_suppress(alert)) {
            stats_.suppressed_alerts++;
            return;
        }

        // 输出告警
        for (auto& output : outputs_) {
            output->output(*alert);
        }

        // 更新去重记录
        if (dedup_config_.enabled) {
            update_dedup_record(alert);
        }
    }

    // 刷新所有输出器
    void flush() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& output : outputs_) {
            output->flush();
        }
    }

    // 关闭所有输出器
    void close() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& output : outputs_) {
            output->close();
        }
    }

    // 获取统计信息
    AlertStatistics get_statistics() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return stats_;
    }

    // 清理过期的去重记录
    void cleanup_dedup_records() {
        std::lock_guard<std::mutex> lock(mutex_);

        auto now = std::chrono::system_clock::now();
        auto window = std::chrono::seconds(dedup_config_.time_window_seconds);

        // 移除过期记录
        for (auto it = dedup_records_.begin(); it != dedup_records_.end(); ) {
            auto& records = it->second;

            // 移除过期的时间戳
            records.erase(
                std::remove_if(records.begin(), records.end(),
                    [&](const std::chrono::system_clock::time_point& ts) {
                        return (now - ts) > window;
                    }),
                records.end()
            );

            // 如果该规则没有记录了，删除整个条目
            if (records.empty()) {
                it = dedup_records_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // 获取告警生成器
    AlertGenerator& get_generator() {
        return generator_;
    }

private:
    AlertGenerator generator_;
    std::vector<std::shared_ptr<AlertOutput>> outputs_;
    DeduplicationConfig dedup_config_;
    AlertStatistics stats_;
    mutable std::mutex mutex_;

    // 去重记录：规则ID -> 时间戳列表
    std::unordered_map<uint32_t, std::vector<std::chrono::system_clock::time_point>> dedup_records_;

    // 判断是否应该抑制告警
    bool should_suppress(const std::shared_ptr<Alert>& alert) {
        auto& records = dedup_records_[alert->signature_id];

        // 清理过期记录
        auto now = std::chrono::system_clock::now();
        auto window = std::chrono::seconds(dedup_config_.time_window_seconds);

        records.erase(
            std::remove_if(records.begin(), records.end(),
                [&](const std::chrono::system_clock::time_point& ts) {
                    return (now - ts) > window;
                }),
            records.end()
        );

        // 检查是否超过阈值
        return records.size() >= dedup_config_.max_alerts_per_rule;
    }

    // 更新去重记录
    void update_dedup_record(const std::shared_ptr<Alert>& alert) {
        dedup_records_[alert->signature_id].push_back(alert->timestamp);
    }

    // 更新优先级统计
    void update_priority_stats(AlertPriority priority) {
        switch (priority) {
            case AlertPriority::CRITICAL:
                stats_.critical_alerts++;
                break;
            case AlertPriority::HIGH:
                stats_.high_alerts++;
                break;
            case AlertPriority::MEDIUM:
                stats_.medium_alerts++;
                break;
            case AlertPriority::LOW:
                stats_.low_alerts++;
                break;
        }
    }
};

} // namespace alerts
} // namespace netguardian

#endif // NETGUARDIAN_ALERTS_ALERT_MANAGER_H
