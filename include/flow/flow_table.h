#ifndef NETGUARDIAN_FLOW_FLOW_TABLE_H
#define NETGUARDIAN_FLOW_FLOW_TABLE_H

#include "flow/flow.h"
#include <unordered_map>
#include <memory>
#include <mutex>
#include <vector>

namespace netguardian {
namespace flow {

// 流表统计信息
struct FlowTableStats {
    uint64_t total_flows;          // 总流数（历史累计）
    uint64_t active_flows;         // 当前活跃流数
    uint64_t total_packets;        // 总处理的数据包数
    uint64_t total_bytes;          // 总处理的字节数

    FlowTableStats()
        : total_flows(0)
        , active_flows(0)
        , total_packets(0)
        , total_bytes(0)
    {}
};

// 流表 - 使用 Hash 表存储流
class FlowTable {
public:
    using FlowPtr = std::shared_ptr<Flow>;

    FlowTable() : stats_() {}

    // 查找流（根据五元组）
    // 如果找到返回流指针，否则返回 nullptr
    FlowPtr find_flow(const FlowKey& key) {
        std::lock_guard<std::mutex> lock(mutex_);

        // 先尝试直接查找
        auto it = flows_.find(key);
        if (it != flows_.end()) {
            return it->second;
        }

        // 再尝试查找反向流
        FlowKey reverse_key = key.reverse();
        it = flows_.find(reverse_key);
        if (it != flows_.end()) {
            return it->second;
        }

        return nullptr;
    }

    // 创建新流
    FlowPtr create_flow(const FlowKey& key) {
        std::lock_guard<std::mutex> lock(mutex_);

        // 检查是否已存在
        auto it = flows_.find(key);
        if (it != flows_.end()) {
            return it->second;  // 已存在，返回现有的
        }

        // 创建新流
        auto flow = std::make_shared<Flow>(key);
        flows_[key] = flow;

        // 更新统计
        stats_.total_flows++;
        stats_.active_flows++;

        return flow;
    }

    // 获取或创建流（如果不存在则创建）
    FlowPtr get_or_create_flow(const FlowKey& key) {
        auto flow = find_flow(key);
        if (!flow) {
            flow = create_flow(key);
        }
        return flow;
    }

    // 删除流
    bool remove_flow(const FlowKey& key) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = flows_.find(key);
        if (it != flows_.end()) {
            flows_.erase(it);
            stats_.active_flows--;
            return true;
        }

        return false;
    }

    // 删除流（根据流 ID）
    bool remove_flow_by_id(uint64_t flow_id) {
        std::lock_guard<std::mutex> lock(mutex_);

        for (auto it = flows_.begin(); it != flows_.end(); ++it) {
            if (it->second->flow_id() == flow_id) {
                flows_.erase(it);
                stats_.active_flows--;
                return true;
            }
        }

        return false;
    }

    // 清空所有流
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        flows_.clear();
        stats_.active_flows = 0;
    }

    // 获取所有流
    std::vector<FlowPtr> get_all_flows() {
        std::lock_guard<std::mutex> lock(mutex_);

        std::vector<FlowPtr> result;
        result.reserve(flows_.size());

        for (const auto& pair : flows_) {
            result.push_back(pair.second);
        }

        return result;
    }

    // 更新流统计（处理一个数据包）
    void update_flow(const FlowKey& key, uint32_t packet_length) {
        auto flow = get_or_create_flow(key);
        if (flow) {
            FlowDirection direction = flow->get_direction(key);
            flow->update(packet_length, direction);

            // 更新全局统计
            stats_.total_packets++;
            stats_.total_bytes += packet_length;
        }
    }

    // 获取流表统计信息
    FlowTableStats get_stats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return stats_;
    }

    // 获取流表大小
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return flows_.size();
    }

    // 遍历所有流（使用回调函数）
    template<typename Func>
    void foreach_flow(Func callback) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& pair : flows_) {
            callback(pair.second);
        }
    }

private:
    std::unordered_map<FlowKey, FlowPtr> flows_;  // 流的 Hash 表
    FlowTableStats stats_;                         // 流表统计信息
    mutable std::mutex mutex_;                     // 线程安全锁
};

} // namespace flow
} // namespace netguardian

#endif // NETGUARDIAN_FLOW_FLOW_TABLE_H
