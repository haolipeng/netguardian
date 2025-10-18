#ifndef NETGUARDIAN_CORE_MT_DETECTION_ENGINE_H
#define NETGUARDIAN_CORE_MT_DETECTION_ENGINE_H

#include "core/detection_engine.h"
#include "core/packet.h"
#include "flow/concurrent_flow_table.h"
#include "utils/packet_queue.h"
#include <thread>
#include <atomic>
#include <vector>

namespace netguardian {
namespace core {

/**
 * 多线程检测引擎配置
 */
struct MTDetectionEngineConfig : public DetectionEngineConfig {
    // 线程配置
    size_t num_worker_threads = 0;  // 0 = 自动检测（CPU核心数-1）
    size_t queue_size = 131072;     // 数据包队列大小（128K）
    size_t flow_table_shards = 256; // 流表分片数量

    // 性能调优
    size_t batch_size = 32;          // 批处理大小
    bool enable_batching = true;     // 启用批处理
    bool enable_cpu_affinity = false; // 启用CPU亲和性
};

/**
 * 多线程检测引擎
 *
 * 架构：
 * 1. 主线程（捕获线程）：捕获数据包并放入无锁队列
 * 2. 工作线程池：从队列中取出数据包并处理
 * 3. 并发流表：使用分片锁优化流查找和更新
 * 4. 统计线程：定期收集和报告统计信息
 */
class MTDetectionEngine {
public:
    explicit MTDetectionEngine(const MTDetectionEngineConfig& config);
    ~MTDetectionEngine();

    // 禁止拷贝
    MTDetectionEngine(const MTDetectionEngine&) = delete;
    MTDetectionEngine& operator=(const MTDetectionEngine&) = delete;

    /**
     * 初始化引擎
     */
    bool initialize();

    /**
     * 启动引擎（启动工作线程）
     */
    void start();

    /**
     * 停止引擎
     */
    void stop();

    /**
     * 处理数据包（由捕获线程调用）
     * 将数据包放入队列，立即返回
     */
    void process_packet(const Packet& packet);

    /**
     * 刷新所有数据（停止前调用）
     */
    void flush();

    /**
     * 获取统计信息
     */
    DetectionEngineStats get_stats() const;

    /**
     * 获取流统计信息
     */
    flow::FlowTableStats get_flow_stats() const;

    /**
     * 获取规则数量
     */
    size_t get_rule_count() const;

    /**
     * 检查引擎是否正在运行
     */
    bool is_running() const { return running_.load(); }

private:
    /**
     * 工作线程函数
     */
    void worker_thread(size_t worker_id);

    /**
     * 批处理数据包
     */
    void process_packet_batch(std::vector<Packet>& batch, size_t worker_id);

    /**
     * 单个数据包处理（类似单线程版本）
     */
    void process_single_packet(Packet& packet, size_t worker_id);

    // 配置
    MTDetectionEngineConfig config_;

    // 运行状态
    std::atomic<bool> running_{false};
    std::atomic<bool> initialized_{false};

    // 数据包队列（使用 moodycamel::ConcurrentQueue）
    utils::PacketQueue packet_queue_;

    // 工作线程
    std::vector<std::thread> workers_;
    size_t num_workers_;

    // 并发流表
    std::unique_ptr<flow::ConcurrentFlowTable> flow_table_;
    std::unique_ptr<flow::FlowManager> flow_manager_;

    // 每个工作线程一份的组件（避免竞争）
    struct PerWorkerComponents {
        // L2-L4 解码器
        std::unique_ptr<decoders::EthernetDecoder> eth_decoder;
        std::unique_ptr<decoders::IPv4Decoder> ipv4_decoder;
        std::unique_ptr<decoders::TcpDecoder> tcp_decoder;
        std::unique_ptr<decoders::UdpDecoder> udp_decoder;

        // L7 解析器
        std::unique_ptr<decoders::HttpParser> http_parser;
        std::unique_ptr<decoders::DnsParser> dns_parser;

        // 重组引擎
        std::unique_ptr<reassembly::TcpReassembler> tcp_reasm;
        std::unique_ptr<reassembly::Ipv4Reassembler> ipv4_reasm;
        std::unique_ptr<reassembly::Ipv6Reassembler> ipv6_reasm;

        // DNS 异常检测
        std::unique_ptr<decoders::DnsAnomalyDetector> dns_anomaly;

        // 局部统计（减少原子操作开销）
        DetectionEngineStats local_stats{};
    };

    std::vector<PerWorkerComponents> worker_components_;

    // 共享组件（线程安全）
    std::unique_ptr<rules::RuleManager> rule_manager_;
    std::unique_ptr<alerts::AlertGenerator> alert_generator_;
    std::unique_ptr<alerts::AlertManager> alert_manager_;

    // 全局统计（原子操作）
    mutable std::atomic<uint64_t> total_packets_{0};
    mutable std::atomic<uint64_t> total_bytes_{0};
    mutable std::atomic<uint64_t> dropped_packets_{0};
    mutable std::atomic<uint64_t> queue_full_drops_{0};
};

} // namespace core
} // namespace netguardian

#endif // NETGUARDIAN_CORE_MT_DETECTION_ENGINE_H
