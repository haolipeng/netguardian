# Pipeline 架构重构总结

## 重构动机

原有的 `DetectionEngine` 命名存在语义混淆：

1. **命名不准确**：系统核心是一个**处理器管道（Pipeline）**，而非单纯的"检测引擎"
2. **职责不清晰**：检测（Detection）只是管道中的一个处理器，不应该是整个系统的核心概念
3. **架构理念不明确**：Pipeline 架构的优势被"检测引擎"这个名字掩盖了

## 重构内容

### 1. 核心类重命名

| 原名称 | 新名称 | 说明 |
|--------|--------|------|
| `DetectionEngine` | `PacketPipeline` | 数据包处理管道 |
| `DetectionEngineConfig` | `PacketPipelineConfig` | 管道配置 |
| `DetectionEngineStats` | `PipelineStats` | 管道统计信息 |
| `DetectionEngineStatsSnapshot` | `PipelineStatsSnapshot` | 统计信息快照 |

### 2. 文件结构变化

#### 新增文件
- **`include/core/packet_pipeline.h`**：新的管道核心类

#### 修改文件
- **`include/core/detection_engine.h`**：改为向后兼容的别名文件
- **`include/core/statistics_collector.h`**：更新统计类型名称
- **`include/core/processor_factory.h`**：更新工厂方法名称
- **`src/main.cpp`**：使用新的 Pipeline 命名

### 3. API 变化

#### ProcessorFactory

**旧 API（已弃用）：**
```cpp
auto engine = ProcessorFactory::create_detection_engine(config);
auto engine = ProcessorFactory::create_custom_engine(processors);
auto engine = ProcessorFactory::create_minimal_engine(DLT_EN10MB);
```

**新 API：**
```cpp
auto pipeline = ProcessorFactory::create_packet_pipeline(config);
auto pipeline = ProcessorFactory::create_custom_pipeline(processors);
auto pipeline = ProcessorFactory::create_minimal_pipeline(DLT_EN10MB);
```

#### 主程序使用示例

**旧方式（仍然兼容）：**
```cpp
#include "core/detection_engine.h"
std::unique_ptr<DetectionEngine> g_engine;
g_engine = ProcessorFactory::create_detection_engine(config);
```

**新方式（推荐）：**
```cpp
#include "core/packet_pipeline.h"
std::unique_ptr<PacketPipeline> g_pipeline;
g_pipeline = ProcessorFactory::create_packet_pipeline(config);
```

### 4. 架构优势

#### Pipeline 设计理念

```
PacketPipeline (管道编排器)
  │
  ├─ ProtocolParsingProcessor   (协议解析)
  ├─ FlowTrackingProcessor      (流跟踪)
  ├─ TcpReassemblyProcessor     (TCP 重组)
  ├─ HttpParsingProcessor       (HTTP 解析)
  ├─ DnsParsingProcessor        (DNS 解析)
  ├─ AnomalyDetectionProcessor  (异常检测)
  └─ RuleDetectionProcessor     (规则检测) ← 检测只是其中一个环节
```

**核心优势：**

1. **职责清晰**
   - Pipeline：只负责编排处理器
   - Processor：各自负责具体的业务逻辑

2. **易于扩展**
   - 添加新功能只需实现新的 Processor
   - 无需修改 Pipeline 核心代码

3. **灵活可配置**
   - 可以动态调整处理器顺序
   - 可以选择性启用/禁用处理器

4. **便于测试**
   - 每个 Processor 可独立测试
   - Pipeline 逻辑简单，易于验证

## 向后兼容性

### 完全兼容

所有旧代码**无需修改**即可正常编译和运行：

```cpp
// 这段旧代码仍然可以正常工作
#include "core/detection_engine.h"

std::unique_ptr<DetectionEngine> engine;
engine = ProcessorFactory::create_detection_engine(config);
engine->initialize();
engine->start();
engine->process_packet(packet);
DetectionEngineStatsSnapshot stats = engine->get_stats_snapshot();
```

### 实现方式

通过 `typedef` 提供别名：

```cpp
// include/core/detection_engine.h
typedef PacketPipeline DetectionEngine;
typedef PacketPipelineConfig DetectionEngineConfig;
typedef PipelineStats DetectionEngineStats;
typedef PipelineStatsSnapshot DetectionEngineStatsSnapshot;
```

### 迁移建议

虽然旧 API 仍然可用，但建议新代码使用新 API：

1. **包含头文件**：`#include "core/packet_pipeline.h"`
2. **使用新类型**：`PacketPipeline` 而非 `DetectionEngine`
3. **使用新工厂方法**：`create_packet_pipeline()` 而非 `create_detection_engine()`

## 编译验证

重构后的代码已通过完整编译测试：

```bash
cd netguardian/build
cmake ..
make -j4
# [100%] Built target netguardian
```

所有测试和示例程序编译成功，无错误。

## 未来计划

### 可选的后续优化

1. **创建专门的 DetectionProcessor**
   - 将 `RuleDetectionProcessor` 和 `AnomalyDetectionProcessor` 合并
   - 提供统一的检测接口

2. **增强 Pipeline 功能**
   - 支持处理器的条件执行
   - 支持处理器的并行执行
   - 支持处理器的动态加载

3. **移除弃用的 API**
   - 在未来的主要版本中移除 `detection_engine.h` 别名
   - 完全切换到 Pipeline 命名体系

## 总结

此次重构：

✅ **提升了语义准确性**：Pipeline 更准确地描述了系统架构
✅ **保持了完全兼容**：所有旧代码无需修改
✅ **改善了代码组织**：职责更加清晰
✅ **增强了可扩展性**：更容易添加新的处理器
✅ **编译测试通过**：100% 编译成功，无错误

**核心理念**：检测引擎（Detection Engine）只是数据包处理管道（Packet Pipeline）中的一个组件，而非整个系统的核心。
