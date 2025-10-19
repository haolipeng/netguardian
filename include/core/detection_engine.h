#ifndef NETGUARDIAN_CORE_DETECTION_ENGINE_H
#define NETGUARDIAN_CORE_DETECTION_ENGINE_H

#include "core/packet_pipeline.h"

namespace netguardian {
namespace core {

/**
 * @deprecated 使用 PacketPipelineConfig 替代
 */
typedef PacketPipelineConfig DetectionEngineConfig;

/**
 * @deprecated 使用 PacketPipeline 替代
 *
 * **重要说明**：
 * DetectionEngine 已重命名为 PacketPipeline，以更准确地反映其设计理念。
 *
 * PacketPipeline 是一个处理器编排器（Orchestrator），负责：
 * - 管理处理器管道（Pipeline）
 * - 依次调用各处理器处理数据包
 * - 提供统计信息访问接口
 *
 * "检测"（Detection）只是管道中的一个处理器，而不是整个系统的核心。
 */
typedef PacketPipeline DetectionEngine;

/**
 * @deprecated 使用 PipelineStats 替代
 */
typedef PipelineStats DetectionEngineStats;

/**
 * @deprecated 使用 PipelineStatsSnapshot 替代
 */
typedef PipelineStatsSnapshot DetectionEngineStatsSnapshot;

} // namespace core
} // namespace netguardian

#endif // NETGUARDIAN_CORE_DETECTION_ENGINE_H
