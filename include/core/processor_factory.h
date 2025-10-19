#ifndef NETGUARDIAN_CORE_PROCESSOR_FACTORY_H
#define NETGUARDIAN_CORE_PROCESSOR_FACTORY_H

#include "core/packet_processor.h"
#include "core/packet_pipeline.h"
#include "processors/protocol_parsing_processor.h"
#include "processors/flow_tracking_processor.h"
#include "processors/tcp_reassembly_processor.h"
#include "processors/ip_reassembly_processor.h"
#include "processors/http_parsing_processor.h"
#include "processors/dns_parsing_processor.h"
#include "processors/anomaly_detection_processor.h"
#include "processors/rule_detection_processor.h"
#include "flow/flow_table.h"
#include "flow/flow_manager.h"
#include "decoders/dns_anomaly_detector.h"
#include "rules/rule_manager.h"
#include "alerts/alert_manager.h"
#include "alerts/alert_output.h"
#include "utils/cxx11_compat.h"
#include <memory>
#include <vector>
#include <string>
#include <iostream>
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

    // 规则检测
    bool enable_rule_detection = false;
    std::string rules_path;  // 规则文件或目录路径

    // 告警输出
    bool enable_console_output = true;   // 控制台输出
    bool enable_file_output = false;      // 文件输出
    std::string alert_file_path;          // 告警文件路径
    std::string alert_file_format;        // 文件格式：text/json/csv
    bool enable_syslog_output = false;    // Syslog 输出

    // 重组
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
 * auto pipeline = ProcessorFactory::create_packet_pipeline(config);
 * pipeline->start();
 * ```
 */
class ProcessorFactory {
public:
    /**
     * 创建标准的数据包处理管道（包含完整的处理器）
     *
     * @param config 处理器配置
     * @return PacketPipeline 智能指针
     */
    static std::unique_ptr<PacketPipeline> create_packet_pipeline(
        const ProcessorFactoryConfig& config = ProcessorFactoryConfig())
    {
        auto pipeline = std::unique_ptr<PacketPipeline>(new PacketPipeline());

        // 创建共享的流表（如果启用流跟踪）
        std::shared_ptr<flow::FlowTable> flow_table;
        if (config.enable_flow_tracking) {
            flow_table = std::make_shared<flow::FlowTable>();
        }

        // 创建并添加处理器（按处理顺序）

        // 1. 协议解析（必需，放在最前面）
        pipeline->add_processor(
            std::unique_ptr<processors::ProtocolParsingProcessor>(new processors::ProtocolParsingProcessor(config.datalink_type))
        );

        // 2. 流跟踪（可选）
        if (config.enable_flow_tracking && flow_table) {
            pipeline->add_processor(
                std::unique_ptr<processors::FlowTrackingProcessor>(new processors::FlowTrackingProcessor(flow_table))
            );
        }

        // 3. IP 分片重组（可选，需在 TCP 重组之前）
        if (config.enable_ip_reassembly) {
            pipeline->add_processor(
                std::unique_ptr<processors::IpReassemblyProcessor>(new processors::IpReassemblyProcessor())
            );
        }

        // 4. TCP 流重组（可选，需要流跟踪支持）
        if (config.enable_tcp_reassembly && config.enable_flow_tracking) {
            pipeline->add_processor(
                std::unique_ptr<processors::TcpReassemblyProcessor>(new processors::TcpReassemblyProcessor())
            );
        }

        // 5. HTTP 解析（可选）
        if (config.enable_http_parser) {
            pipeline->add_processor(
                std::unique_ptr<processors::HttpParsingProcessor>(new processors::HttpParsingProcessor())
            );
        }

        // 6. DNS 解析（可选）
        if (config.enable_dns_parser) {
            pipeline->add_processor(
                std::unique_ptr<processors::DnsParsingProcessor>(new processors::DnsParsingProcessor())
            );
        }

        // 7. 异常检测（可选）
        if (config.enable_dns_anomaly_detection) {
            auto dns_detector = std::make_shared<decoders::DnsAnomalyDetector>(
                config.dns_anomaly_config
            );
            pipeline->add_processor(
                std::unique_ptr<processors::AnomalyDetectionProcessor>(new processors::AnomalyDetectionProcessor(dns_detector))
            );
        }

        // 8. 规则检测（可选）
        if (config.enable_rule_detection && !config.rules_path.empty()) {
            // 创建规则管理器
            auto rule_manager = std::make_shared<rules::RuleManager>();
            if (!rule_manager->load_rules_file(config.rules_path)) {
                // 加载失败时记录错误但继续
                std::cerr << "[WARN] Failed to load rules from: " << config.rules_path << "\n";
            }

            // 创建告警管理器
            auto alert_manager = std::make_shared<alerts::AlertManager>();

            // 添加控制台输出
            if (config.enable_console_output) {
                alert_manager->add_output(
                    std::make_shared<alerts::ConsoleAlertOutput>()
                );
            }

            // 添加文件输出
            if (config.enable_file_output && !config.alert_file_path.empty()) {
                try {
                    alerts::FileAlertOutput::FileFormat format = alerts::FileAlertOutput::FileFormat::TEXT;

                    // 根据配置或文件扩展名确定格式
                    if (!config.alert_file_format.empty()) {
                        if (config.alert_file_format == "json") {
                            format = alerts::FileAlertOutput::FileFormat::JSON;
                        } else if (config.alert_file_format == "csv") {
                            format = alerts::FileAlertOutput::FileFormat::CSV;
                        }
                    } else {
                        // 根据文件扩展名自动检测
                        std::string path = config.alert_file_path;
                        if (path.size() >= 5 && path.substr(path.size() - 5) == ".json") {
                            format = alerts::FileAlertOutput::FileFormat::JSON;
                        } else if (path.size() >= 4 && path.substr(path.size() - 4) == ".csv") {
                            format = alerts::FileAlertOutput::FileFormat::CSV;
                        }
                    }

                    alert_manager->add_output(
                        std::make_shared<alerts::FileAlertOutput>(config.alert_file_path, format)
                    );
                } catch (const std::exception& e) {
                    std::cerr << "[WARN] Failed to create file alert output: " << e.what() << "\n";
                }
            }

            // 添加 Syslog 输出
            if (config.enable_syslog_output) {
                alert_manager->add_output(
                    std::make_shared<alerts::SyslogAlertOutput>()
                );
            }

            // 创建规则检测处理器
            pipeline->add_processor(
                std::make_unique<processors::RuleDetectionProcessor>(
                    rule_manager,
                    alert_manager
                )
            );
        }

        return pipeline;
    }

    /**
     * 创建自定义的处理器管道
     *
     * @param processors 处理器列表（按顺序）
     * @return PacketPipeline 智能指针
     */
    static std::unique_ptr<PacketPipeline> create_custom_pipeline(
        std::vector<PacketProcessorPtr> processors)
    {
        auto pipeline = std::unique_ptr<PacketPipeline>(new PacketPipeline());

        for (auto& processor : processors) {
            pipeline->add_processor(std::move(processor));
        }

        return pipeline;
    }

    /**
     * 创建最小化的管道（仅协议解析）
     *
     * @param datalink_type Datalink 类型
     * @return PacketPipeline 智能指针
     */
    static std::unique_ptr<PacketPipeline> create_minimal_pipeline(
        int datalink_type = DLT_EN10MB)
    {
        auto pipeline = std::unique_ptr<PacketPipeline>(new PacketPipeline());

        pipeline->add_processor(
            std::unique_ptr<processors::ProtocolParsingProcessor>(new processors::ProtocolParsingProcessor(datalink_type))
        );

        return pipeline;
    }
};

} // namespace core
} // namespace netguardian

#endif // NETGUARDIAN_CORE_PROCESSOR_FACTORY_H
