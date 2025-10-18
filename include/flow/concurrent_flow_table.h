#ifndef NETGUARDIAN_FLOW_CONCURRENT_FLOW_TABLE_H
#define NETGUARDIAN_FLOW_CONCURRENT_FLOW_TABLE_H

#include "flow/flow.h"
#include "flow/flow_key.h"
#include "flow/flow_table.h"
#include <unordered_map>
#include <shared_mutex>
#include <vector>
#include <atomic>

namespace netguardian {
namespace flow {

/**
 * 并发流表 - 使用分片锁优化并发性能
 *
 * 原理：将哈希表分成多个桶（shard），每个桶有独立的锁
 * 这样不同的流可以并发访问不同的桶，大幅提升并发性能
 */
class ConcurrentFlowTable {
public:
    using FlowPtr = std::shared_ptr<Flow>;

    /**
     * 构造函数
     * @param num_shards 分片数量，建议为2的幂次方，默认256
     * @param max_flows_per_shard 每个分片的最大流数
     */
    explicit ConcurrentFlowTable(size_t num_shards = 256, size_t max_flows_per_shard = 4096)
        : num_shards_(num_shards)
        , max_flows_per_shard_(max_flows_per_shard)
        , shards_(num_shards)
    {
        for (auto& shard : shards_) {
            shard.flows.reserve(max_flows_per_shard / 2);
        }
    }

    /**
     * 查找流
     * 使用读锁，允许多个线程并发读取同一个shard
     */
    FlowPtr find_flow(const FlowKey& key) {
        size_t shard_idx = get_shard_index(key);
        auto& shard = shards_[shard_idx];

        // 使用共享锁（读锁）
        std::shared_lock<std::shared_mutex> lock(shard.mutex);

        // 先尝试直接查找
        auto it = shard.flows.find(key);
        if (it != shard.flows.end()) {
            shard.stats.hits++;
            return it->second;
        }

        // 尝试查找反向流
        FlowKey reverse_key = key.reverse();
        it = shard.flows.find(reverse_key);
        if (it != shard.flows.end()) {
            shard.stats.hits++;
            return it->second;
        }

        shard.stats.misses++;
        return nullptr;
    }

    /**
     * 创建新流
     * 使用独占锁（写锁）
     */
    FlowPtr create_flow(const FlowKey& key) {
        size_t shard_idx = get_shard_index(key);
        auto& shard = shards_[shard_idx];

        // 使用独占锁（写锁）
        std::unique_lock<std::shared_mutex> lock(shard.mutex);

        // 检查是否已存在（双重检查）
        auto it = shard.flows.find(key);
        if (it != shard.flows.end()) {
            return it->second;
        }

        FlowKey reverse_key = key.reverse();
        it = shard.flows.find(reverse_key);
        if (it != shard.flows.end()) {
            return it->second;
        }

        // 检查流数量限制
        if (shard.flows.size() >= max_flows_per_shard_) {
            shard.stats.evictions++;
            // 简单的 LRU：删除第一个流（可以改进）
            shard.flows.erase(shard.flows.begin());
        }

        // 创建新流
        auto flow = std::make_shared<Flow>(key);
        shard.flows[key] = flow;
        shard.stats.total_flows++;
        shard.stats.active_flows = shard.flows.size();

        return flow;
    }

    /**
     * 获取或创建流（原子操作）
     */
    FlowPtr get_or_create_flow(const FlowKey& key) {
        // 先尝试查找（使用读锁）
        FlowPtr flow = find_flow(key);
        if (flow) {
            return flow;
        }

        // 没找到，创建新流（使用写锁）
        return create_flow(key);
    }

    /**
     * 删除流
     */
    bool remove_flow(const FlowKey& key) {
        size_t shard_idx = get_shard_index(key);
        auto& shard = shards_[shard_idx];

        std::unique_lock<std::shared_mutex> lock(shard.mutex);

        auto it = shard.flows.find(key);
        if (it != shard.flows.end()) {
            shard.flows.erase(it);
            shard.stats.active_flows = shard.flows.size();
            return true;
        }

        FlowKey reverse_key = key.reverse();
        it = shard.flows.find(reverse_key);
        if (it != shard.flows.end()) {
            shard.flows.erase(it);
            shard.stats.active_flows = shard.flows.size();
            return true;
        }

        return false;
    }

    /**
     * 遍历所有流并应用函数
     * 注意：这个操作会锁定所有shard，代价较高
     */
    template<typename Func>
    void for_each_flow(Func&& func) {
        for (auto& shard : shards_) {
            std::shared_lock<std::shared_mutex> lock(shard.mutex);
            for (auto& [key, flow] : shard.flows) {
                func(flow);
            }
        }
    }

    /**
     * 清理超时流
     * @return 清理的流数量
     */
    size_t cleanup_expired_flows(const FlowTimeoutConfig& timeout_config) {
        size_t cleaned = 0;
        auto now = std::chrono::steady_clock::now();

        for (auto& shard : shards_) {
            std::unique_lock<std::shared_mutex> lock(shard.mutex);

            for (auto it = shard.flows.begin(); it != shard.flows.end();) {
                auto& flow = it->second;

                // 计算超时时间
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - flow->last_packet_time()).count();

                bool should_timeout = false;

                if (flow->protocol() == IPPROTO_TCP) {
                    auto tcp_state = flow->tcp_state();
                    if (tcp_state == TcpState::ESTABLISHED) {
                        should_timeout = elapsed > timeout_config.tcp_established_timeout;
                    } else if (tcp_state == TcpState::CLOSING || tcp_state == TcpState::LAST_ACK) {
                        should_timeout = elapsed > timeout_config.tcp_closing_timeout;
                    } else if (tcp_state == TcpState::CLOSED || tcp_state == TcpState::TIME_WAIT) {
                        should_timeout = elapsed > timeout_config.tcp_closed_timeout;
                    } else {
                        should_timeout = elapsed > timeout_config.tcp_unknown_timeout;
                    }
                } else if (flow->protocol() == IPPROTO_UDP) {
                    should_timeout = elapsed > timeout_config.udp_timeout;
                } else {
                    should_timeout = elapsed > timeout_config.other_timeout;
                }

                if (should_timeout) {
                    it = shard.flows.erase(it);
                    cleaned++;
                    shard.stats.timeouts++;
                } else {
                    ++it;
                }
            }

            shard.stats.active_flows = shard.flows.size();
        }

        return cleaned;
    }

    /**
     * 获取统计信息
     */
    FlowTableStats get_stats() const {
        FlowTableStats total_stats{};

        for (const auto& shard : shards_) {
            // 注意：这里不加锁，统计可能略有误差，但避免性能开销
            total_stats.active_flows += shard.stats.active_flows;
            total_stats.total_flows += shard.stats.total_flows;
            total_stats.hits += shard.stats.hits;
            total_stats.misses += shard.stats.misses;
            total_stats.timeouts += shard.stats.timeouts;
            total_stats.evictions += shard.stats.evictions;
        }

        total_stats.hit_rate = total_stats.hits + total_stats.misses > 0
            ? static_cast<double>(total_stats.hits) / (total_stats.hits + total_stats.misses)
            : 0.0;

        return total_stats;
    }

    /**
     * 获取每个shard的统计信息（用于性能分析）
     */
    std::vector<FlowTableStats> get_shard_stats() const {
        std::vector<FlowTableStats> shard_stats;
        shard_stats.reserve(num_shards_);

        for (const auto& shard : shards_) {
            shard_stats.push_back(shard.stats);
        }

        return shard_stats;
    }

    /**
     * 清空所有流
     */
    void clear() {
        for (auto& shard : shards_) {
            std::unique_lock<std::shared_mutex> lock(shard.mutex);
            shard.flows.clear();
            shard.stats = FlowTableStats{};
        }
    }

    /**
     * 获取总流数量
     */
    size_t size() const {
        size_t total = 0;
        for (const auto& shard : shards_) {
            total += shard.stats.active_flows;
        }
        return total;
    }

    /**
     * 获取分片数量
     */
    size_t num_shards() const {
        return num_shards_;
    }

private:
    /**
     * 计算流应该在哪个shard中
     * 使用FlowKey的哈希值分配shard
     */
    size_t get_shard_index(const FlowKey& key) const {
        // 使用 FlowKey 的哈希函数
        size_t hash = std::hash<FlowKey>{}(key);

        // 快速模运算（假设 num_shards 是2的幂次方）
        if ((num_shards_ & (num_shards_ - 1)) == 0) {
            return hash & (num_shards_ - 1);
        }

        return hash % num_shards_;
    }

    struct Shard {
        mutable std::shared_mutex mutex;
        std::unordered_map<FlowKey, FlowPtr> flows;
        FlowTableStats stats{};
    };

    const size_t num_shards_;
    const size_t max_flows_per_shard_;
    std::vector<Shard> shards_;
};

} // namespace flow
} // namespace netguardian

#endif // NETGUARDIAN_FLOW_CONCURRENT_FLOW_TABLE_H
