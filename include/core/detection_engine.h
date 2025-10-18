#ifndef NETGUARDIAN_CORE_DETECTION_ENGINE_H
#define NETGUARDIAN_CORE_DETECTION_ENGINE_H

#include "core/packet.h"
#include "core/packet_processor.h"
#include "core/packet_context.h"
#include "core/statistics_collector.h"
#include "flow/flow_table.h"
#include <vector>
#include <memory>
#include <atomic>
#include <iostream>
#include <stdexcept>

namespace netguardian {
namespace core {

/**
 * DetectionEngineConfig - 检测引擎配置
 *
 * 简化后的配置结构，具体功能的配置由各 Processor 管理
 */
struct DetectionEngineConfig {
    // 基本配置
    bool verbose = false;

    // 默认构造函数
    DetectionEngineConfig() = default;
};

/**
 * DetectionEngine - 检测引擎（重构版本）
 *
 * **设计理念：Pipeline 架构**
 *
 * DetectionEngine 现在是一个 **编排器（Orchestrator）**，其唯一职责是：
 * - 管理处理器管道（Pipeline）
 * - 依次调用各处理器处理数据包
 * - 提供统计信息访问接口
 *
 * **优点**：
 * - 单一职责：只做编排
 * - 可扩展：添加新功能只需添加新的 Processor
 * - 可测试：每个 Processor 可独立测试
 * - 灵活：可以动态调整 Pipeline 顺序
 */
class DetectionEngine {
public:
    /**
     * 构造函数
     *
     * @param config 配置
     */
    explicit DetectionEngine(const DetectionEngineConfig& config = DetectionEngineConfig())
        : config_(config)
        , stats_collector_(std::make_shared<StatisticsCollector>())
        , running_(false)
        , initialized_(false)
    {}

    /**
     * 析构函数
     */
    ~DetectionEngine() {
        stop();
    }

    // 禁止拷贝
    DetectionEngine(const DetectionEngine&) = delete;
    DetectionEngine& operator=(const DetectionEngine&) = delete;

    // ========================================================================
    // Pipeline 管理
    // ========================================================================

    /**
     * 添加处理器到管道
     *
     * 处理器会按添加顺序依次执行
     *
     * @param processor 处理器（unique_ptr，转移所有权）
     */
    void add_processor(PacketProcessorPtr processor) {
        if (running_) {
            throw std::runtime_error("Cannot add processor while engine is running");
        }
        pipeline_.push_back(std::move(processor));
    }

    /**
     * 获取处理器数量
     */
    size_t processor_count() const {
        return pipeline_.size();
    }

    // ========================================================================
    // 生命周期管理
    // ========================================================================

    /**
     * 初始化引擎
     *
     * 调用所有处理器的 initialize() 方法
     *
     * @return true 成功，false 失败
     */
    bool initialize() {
        if (initialized_) {
            return true;
        }

        if (config_.verbose) {
            std::cout << "[INFO] Initializing detection engine with "
                      << pipeline_.size() << " processors...\n";
        }

        // 初始化所有处理器
        for (auto& processor : pipeline_) {
            if (!processor->initialize()) {
                std::cerr << "[ERROR] Failed to initialize processor: "
                          << processor->name() << "\n";
                return false;
            }

            if (config_.verbose) {
                std::cout << "  ✓ " << processor->name() << " initialized\n";
            }
        }

        initialized_ = true;

        if (config_.verbose) {
            std::cout << "[INFO] Detection engine initialized successfully\n\n";
        }

        return true;
    }

    /**
     * 启动引擎
     */
    void start() {
        if (!initialized_) {
            if (!initialize()) {
                throw std::runtime_error("Detection engine initialization failed");
            }
        }
        running_ = true;

        if (config_.verbose) {
            std::cout << "[INFO] Detection engine started\n";
        }
    }

    /**
     * 停止引擎
     */
    void stop() {
        running_ = false;
        flush();

        if (config_.verbose) {
            std::cout << "[INFO] Detection engine stopped\n";
        }
    }

    /**
     * 刷新所有处理器
     *
     * 调用所有处理器的 flush() 方法（导出流、刷新缓冲区等）
     */
    void flush() {
        for (auto& processor : pipeline_) {
            processor->flush();
        }
    }

    /**
     * 关闭引擎
     *
     * 调用所有处理器的 shutdown() 方法
     */
    void shutdown() {
        for (auto& processor : pipeline_) {
            processor->shutdown();
        }
    }

    // ========================================================================
    // 数据包处理
    // ========================================================================

    /**
     * 处理数据包
     *
     * 这是核心方法，依次调用管道中的所有处理器
     *
     * @param packet 数据包（const 引用，但 PacketContext 中会创建可修改副本）
     */
    void process_packet(const Packet& packet) {
        if (!running_ || !initialized_) {
            return;
        }

        // 记录数据包统计
        stats_collector_->record_packet(packet);

        // 创建可修改的数据包副本（用于协议解析）
        Packet mutable_packet = packet;

        // 创建处理上下文
        PacketContext ctx(mutable_packet, *stats_collector_);

        // 依次执行管道中的处理器
        for (auto& processor : pipeline_) {
            ProcessResult result = processor->process(ctx);

            // 根据返回结果决定是否继续
            if (result == ProcessResult::DROP) {
                // 数据包被丢弃
                stats_collector_->record_dropped_packet();
                return;
            } else if (result == ProcessResult::STOP) {
                // 正常停止（无需记录为丢弃）
                return;
            }
            // ProcessResult::CONTINUE - 继续下一个处理器
        }
    }

    // ========================================================================
    // 统计信息
    // ========================================================================

    /**
     * 获取统计信息（引用）
     */
    const DetectionEngineStats& get_stats() const {
        return stats_collector_->stats();
    }

    /**
     * 获取统计信息快照（线程安全）
     */
    DetectionEngineStatsSnapshot get_stats_snapshot() const {
        return stats_collector_->snapshot();
    }

    /**
     * 重置统计信息
     */
    void reset_stats() {
        stats_collector_->reset();
    }

    /**
     * 获取统计收集器（用于外部访问）
     */
    std::shared_ptr<StatisticsCollector> stats_collector() const {
        return stats_collector_;
    }

    // ========================================================================
    // 状态查询
    // ========================================================================

    bool is_running() const { return running_; }
    bool is_initialized() const { return initialized_; }

private:
    // 配置
    DetectionEngineConfig config_;

    // 统计收集器
    std::shared_ptr<StatisticsCollector> stats_collector_;

    // 处理器管道
    std::vector<PacketProcessorPtr> pipeline_;

    // 运行状态
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
};

} // namespace core
} // namespace netguardian

#endif // NETGUARDIAN_CORE_DETECTION_ENGINE_H
