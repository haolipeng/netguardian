#ifndef NETGUARDIAN_CORE_PROCESSOR_FACTORY_H
#define NETGUARDIAN_CORE_PROCESSOR_FACTORY_H

#include "core/packet_processor.h"
#include "core/detection_engine.h"
#include "processors/protocol_parsing_processor.h"
#include "processors/flow_tracking_processor.h"
#include "processors/http_parsing_processor.h"
#include "processors/dns_parsing_processor.h"
#include "processors/anomaly_detection_processor.h"
#include "flow/flow_table.h"
#include "flow/flow_manager.h"
#include "decoders/dns_anomaly_detector.h"
#include <memory>
#include <vector>
#include <pcap/pcap.h>

namespace netguardian {
namespace core {

/**
 * ProcessorFactoryConfig - 处理器工厂配置
 *
 * 用于配置要创建哪些处理器
 */
struct ProcessorFactoryConfig {
    // Datalink 类型
    int datalink_type = DLT_EN10MB;

    // 流管理
    bool enable_flow_tracking = true;
    flow::FlowTimeoutConfig flow_timeout_config;
    uint32_t max_flows = 100000;

    // L7 解析
    bool enable_http_parser = true;
    bool enable_dns_parser = true;

    // 异常检测
    bool enable_dns_anomaly_detection = true;
    decoders::DnsAnomalyConfig dns_anomaly_config;

    // 规则检测（未来扩展）
    bool enable_rule_detection = false;

    // 重组（未来扩展）
    bool enable_tcp_reassembly = false;
    bool enable_ip_reassembly = false;

    ProcessorFactoryConfig() {
        // 流超时默认配置
        flow_timeout_config.tcp_established_timeout = 3600;
        flow_timeout_config.tcp_closing_timeout = 120;
        flow_timeout_config.tcp_closed_timeout = 5;
        flow_timeout_config.tcp_unknown_timeout = 300;
        flow_timeout_config.udp_timeout = 30;
        flow_timeout_config.other_timeout = 30;
    }
};

/**
 * ProcessorFactory - 处理器工厂
 *
 * 提供便捷的方法创建标准的处理器管道
 *
 * 使用示例：
 * ```cpp
 * ProcessorFactoryConfig config;
 * config.enable_http_parser = true;
 * config.enable_dns_parser = true;
 *
 * auto engine = ProcessorFactory::create_detection_engine(config);
 * engine->start();
 * ```
 */
class ProcessorFactory {
public:
    /**
     * 创建标准的检测引擎（包含完整的处理器管道）
     *
     * @param config 处理器配置
     * @return DetectionEngine 智能指针
     */
    static std::unique_ptr<DetectionEngine> create_detection_engine(
        const ProcessorFactoryConfig& config = ProcessorFactoryConfig())
    {
        auto engine = std::make_unique<DetectionEngine>();

        // 创建共享的流表（如果启用流跟踪）
        std::shared_ptr<flow::FlowTable> flow_table;
        if (config.enable_flow_tracking) {
            flow_table = std::make_shared<flow::FlowTable>();
        }

        // 创建并添加处理器（按处理顺序）

        // 1. 协议解析（必需，放在最前面）
        engine->add_processor(
            std::make_unique<processors::ProtocolParsingProcessor>(config.datalink_type)
        );

        // 2. 流跟踪（可选）
        if (config.enable_flow_tracking && flow_table) {
            engine->add_processor(
                std::make_unique<processors::FlowTrackingProcessor>(flow_table)
            );
        }

        // 3. 重组（可选，未来实现）
        // if (config.enable_tcp_reassembly) {
        //     engine->add_processor(
        //         std::make_unique<processors::TcpReassemblyProcessor>(...)
        //     );
        // }
        // if (config.enable_ip_reassembly) {
        //     engine->add_processor(
        //         std::make_unique<processors::IpReassemblyProcessor>(...)
        //     );
        // }

        // 4. HTTP 解析（可选）
        if (config.enable_http_parser) {
            engine->add_processor(
                std::make_unique<processors::HttpParsingProcessor>()
            );
        }

        // 5. DNS 解析（可选）
        if (config.enable_dns_parser) {
            engine->add_processor(
                std::make_unique<processors::DnsParsingProcessor>()
            );
        }

        // 6. 异常检测（可选）
        if (config.enable_dns_anomaly_detection) {
            auto dns_detector = std::make_shared<decoders::DnsAnomalyDetector>(
                config.dns_anomaly_config
            );
            engine->add_processor(
                std::make_unique<processors::AnomalyDetectionProcessor>(dns_detector)
            );
        }

        // 7. 规则检测（可选，未来实现）
        // if (config.enable_rule_detection) {
        //     engine->add_processor(
        //         std::make_unique<processors::RuleDetectionProcessor>(...)
        //     );
        // }

        return engine;
    }

    /**
     * 创建自定义的处理器管道
     *
     * @param processors 处理器列表（按顺序）
     * @return DetectionEngine 智能指针
     */
    static std::unique_ptr<DetectionEngine> create_custom_engine(
        std::vector<PacketProcessorPtr> processors)
    {
        auto engine = std::make_unique<DetectionEngine>();

        for (auto& processor : processors) {
            engine->add_processor(std::move(processor));
        }

        return engine;
    }

    /**
     * 创建最小化的引擎（仅协议解析）
     *
     * @param datalink_type Datalink 类型
     * @return DetectionEngine 智能指针
     */
    static std::unique_ptr<DetectionEngine> create_minimal_engine(
        int datalink_type = DLT_EN10MB)
    {
        auto engine = std::make_unique<DetectionEngine>();

        engine->add_processor(
            std::make_unique<processors::ProtocolParsingProcessor>(datalink_type)
        );

        return engine;
    }
};

} // namespace core
} // namespace netguardian

#endif // NETGUARDIAN_CORE_PROCESSOR_FACTORY_H
