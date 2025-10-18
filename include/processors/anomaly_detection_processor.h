#ifndef NETGUARDIAN_PROCESSORS_ANOMALY_DETECTION_PROCESSOR_H
#define NETGUARDIAN_PROCESSORS_ANOMALY_DETECTION_PROCESSOR_H

#include "core/packet_processor.h"
#include "core/packet_context.h"
#include "decoders/dns_anomaly_detector.h"
#include <memory>
#include <iostream>

namespace netguardian {
namespace processors {

/**
 * AnomalyDetectionProcessor - 异常检测处理器
 *
 * 职责：
 * - 对已解析的协议数据进行异常检测
 * - 当前支持：DNS 异常检测
 * - 记录异常统计
 * - 输出异常告警
 *
 * 注意：
 * - 需要在相应的解析处理器之后运行
 * - 可扩展支持其他协议的异常检测
 */
class AnomalyDetectionProcessor : public core::PacketProcessor {
public:
    /**
     * 构造函数
     *
     * @param dns_detector DNS 异常检测器（可选）
     */
    explicit AnomalyDetectionProcessor(
        std::shared_ptr<decoders::DnsAnomalyDetector> dns_detector = nullptr)
        : dns_detector_(dns_detector)
    {}

    const char* name() const override {
        return "AnomalyDetectionProcessor";
    }

    bool initialize() override {
        // 如果未提供检测器，使用默认配置创建
        if (!dns_detector_) {
            decoders::DnsAnomalyConfig config;
            dns_detector_ = std::make_shared<decoders::DnsAnomalyDetector>(config);
        }
        return true;
    }

    core::ProcessResult process(core::PacketContext& ctx) override {
        // DNS 异常检测
        if (ctx.has_dns_message() && dns_detector_) {
            detect_dns_anomalies(ctx);
        }

        // 未来可以添加其他协议的异常检测
        // if (ctx.has_http_request()) {
        //     detect_http_anomalies(ctx);
        // }

        return core::ProcessResult::CONTINUE;
    }

private:
    /**
     * DNS 异常检测
     */
    void detect_dns_anomalies(core::PacketContext& ctx) {
        auto anomalies = dns_detector_->detect(*ctx.dns_message());

        if (!anomalies.empty()) {
            ctx.stats().record_anomalies(anomalies.size());

            // 输出异常信息（实际应该通过告警系统）
            for (const auto& anomaly : anomalies) {
                std::cout << "[ANOMALY] " << anomaly.to_string() << "\n";
            }
        }
    }

    std::shared_ptr<decoders::DnsAnomalyDetector> dns_detector_;
};

} // namespace processors
} // namespace netguardian

#endif // NETGUARDIAN_PROCESSORS_ANOMALY_DETECTION_PROCESSOR_H
