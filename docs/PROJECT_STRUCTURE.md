# NetGuardian 项目结构说明

## 目录结构

```
netguardian/
├── build/                    # 构建输出目录（git忽略）
│   ├── bin/                 # 可执行文件
│   ├── lib/                 # 库文件
│   └── ...                  # CMake 生成的文件
│
├── cmake/                    # CMake 模块和脚本
│   └── modules/             # 查找第三方库的模块
│
├── docs/                     # 项目文档
│   ├── PROJECT_STATUS.md            # 项目进度和功能状态
│   ├── PROJECT_STRUCTURE.md         # 项目结构说明（本文档）
│   ├── MULTITHREADING_OPTIMIZATION.md  # 多线程优化设计
│   ├── SNORT3_TCP_REASSEMBLY_ANALYSIS.md  # Snort3 TCP重组分析
│   ├── developer/           # 开发者文档
│   └── user/                # 用户文档
│
├── examples/                 # 示例程序
│   ├── basic_capture.cpp            # 基础数据包捕获示例
│   ├── decoder_demo.cpp             # 协议解码示例
│   ├── flow_tracking_demo.cpp       # 流跟踪示例
│   ├── flow_management_demo.cpp     # 流管理示例
│   ├── protocol_identification_demo.cpp  # 协议识别示例
│   ├── example_tcp_reassembly.cpp   # TCP重组示例
│   ├── example_ip_reassembly.cpp    # IP分片重组示例
│   ├── rule_parser_demo.cpp         # 规则解析示例
│   ├── matcher_demo.cpp             # 模式匹配示例
│   ├── example_alert_system.cpp     # 告警系统示例
│   ├── example_http_parser.cpp      # HTTP解析示例
│   ├── example_dns_parser.cpp       # DNS解析示例
│   ├── test_traffic.pcap            # 测试PCAP文件
│   └── netguardian.conf.example     # 配置文件示例
│
├── include/                  # 头文件目录
│   ├── alerts/              # 告警系统
│   │   ├── alert.h                  # 告警数据结构
│   │   ├── alert_generator.h        # 告警生成器
│   │   ├── alert_manager.h          # 告警管理器
│   │   └── alert_output.h           # 告警输出（控制台/文件/Syslog）
│   │
│   ├── core/                # 核心组件
│   │   ├── packet.h                 # 数据包结构
│   │   ├── packet_capture.h         # 数据包捕获（libpcap）
│   │   ├── protocol_types.h         # 协议类型定义
│   │   ├── protocol_parser.h        # 协议解析器基类
│   │   ├── app_protocol_identifier.h # 应用层协议识别
│   │   ├── flow.h                   # 流对象
│   │   ├── session.h                # 会话对象
│   │   ├── config.h                 # 配置管理
│   │   ├── logger.h                 # 日志系统
│   │   ├── engine.h                 # 检测引擎基类
│   │   ├── detection_engine.h       # 单线程检测引擎
│   │   └── mt_detection_engine.h    # 多线程检测引擎
│   │
│   ├── decoders/            # 协议解码器
│   │   ├── ethernet_decoder.h       # 以太网解码器
│   │   ├── ipv4_decoder.h           # IPv4解码器
│   │   ├── ipv6_decoder.h           # IPv6解码器
│   │   ├── tcp_decoder.h            # TCP解码器
│   │   ├── udp_decoder.h            # UDP解码器
│   │   ├── icmp_decoder.h           # ICMP解码器
│   │   ├── http_parser.h            # HTTP解析器
│   │   ├── dns_parser.h             # DNS解析器
│   │   └── dns_anomaly_detector.h   # DNS异常检测
│   │
│   ├── flow/                # 流管理
│   │   ├── flow_key.h               # 流键（五元组）
│   │   ├── flow.h                   # 流对象
│   │   ├── flow_table.h             # 流表（单线程）
│   │   ├── concurrent_flow_table.h  # 并发流表（多线程）
│   │   ├── flow_manager.h           # 流管理器
│   │   └── tcp_state.h              # TCP状态机
│   │
│   ├── reassembly/          # 重组引擎
│   │   ├── tcp_reassembler.h        # TCP流重组
│   │   ├── ipv4_reassembler.h       # IPv4分片重组
│   │   └── ipv6_reassembler.h       # IPv6分片重组
│   │
│   ├── rules/               # 规则引擎
│   │   ├── rule.h                   # 规则数据结构
│   │   ├── rule_parser.h            # 规则解析器（Snort语法）
│   │   ├── rule_manager.h           # 规则管理器
│   │   └── rule_option.h            # 规则选项
│   │
│   ├── matchers/            # 模式匹配引擎
│   │   ├── matcher.h                # 匹配器接口
│   │   ├── ac_matcher.h             # AC自动机匹配器
│   │   ├── regex_matcher.h          # 正则表达式匹配器
│   │   └── pcre_matcher.h           # PCRE匹配器
│   │
│   ├── utils/               # 实用工具
│   │   ├── packet_queue.h           # 高性能数据包队列
│   │   ├── thread_pool.h            # 线程池
│   │   ├── byte_utils.h             # 字节处理工具
│   │   ├── string_utils.h           # 字符串工具
│   │   └── time_utils.h             # 时间工具
│   │
│   ├── bridge/              # Snort/Zeek 桥接层
│   │   └── ...
│   │
│   ├── snort/               # Snort3 集成
│   │   └── ...
│   │
│   └── zeek/                # Zeek 集成
│       └── ...
│
├── src/                      # 源文件目录（与include对应）
│   ├── alerts/
│   ├── core/
│   │   ├── main.cpp                 # 主程序入口
│   │   ├── detection_engine.cpp
│   │   ├── mt_detection_engine.cpp
│   │   └── ...
│   ├── decoders/
│   ├── flow/
│   ├── reassembly/
│   ├── rules/
│   ├── matchers/
│   ├── bridge/
│   ├── snort/
│   └── zeek/
│
├── scripts/                  # 辅助脚本
│   ├── clean.sh                     # 清理构建产物脚本
│   └── generate_test_pcap.py        # 生成测试PCAP文件
│
├── tests/                    # 测试代码
│   ├── unit/                # 单元测试
│   └── integration/         # 集成测试
│
├── third_party/             # 第三方库
│   └── concurrentqueue/     # 高性能无锁队列
│
├── CMakeLists.txt           # 根CMake配置
├── .gitignore               # Git忽略文件配置
└── README.md                # 项目说明
```

## 核心模块说明

### 1. Core（核心层）

**职责：** 基础数据结构和数据包处理管道

**关键组件：**
- `Packet`: 数据包封装，包含原始数据和协议栈信息
- `PacketCapture`: libpcap封装，支持实时捕获和离线分析
- `DetectionEngine`: 检测引擎，整合所有模块
- `MTDetectionEngine`: 多线程版本，使用无锁队列和工作线程池

### 2. Decoders（解码器层）

**职责：** L2-L7 协议解析

**层次结构：**
```
L2: Ethernet
 ↓
L3: IPv4/IPv6, ICMP
 ↓
L4: TCP/UDP
 ↓
L7: HTTP, DNS, TLS, SSH, FTP...
```

**特点：**
- 增量解析：每层解析器只处理自己的协议头
- 协议栈追踪：Packet对象维护完整的协议栈信息
- 深度解析：L7解析器提供完整的应用层语义

### 3. Flow Management（流管理层）

**职责：** 网络流跟踪和状态管理

**关键功能：**
- 五元组流识别（src_ip, dst_ip, src_port, dst_port, protocol）
- TCP状态机（11种状态）
- 流超时管理
- 双向流量统计

**并发优化：**
- 单线程版：`FlowTable`（单个mutex）
- 多线程版：`ConcurrentFlowTable`（256个shard，分片锁）

### 4. Reassembly（重组层）

**职责：** TCP流重组和IP分片重组

**实现：**
- `TcpReassembler`: 双向TCP流重组，处理乱序和重传
- `Ipv4Reassembler`: IPv4分片重组
- `Ipv6Reassembler`: IPv6分片重组

### 5. Rules Engine（规则引擎）

**职责：** 规则解析、管理和匹配

**组件：**
- `RuleParser`: 解析Snort语法规则
- `RuleManager`: 规则加载、启用/禁用、查询
- `Rule`: 规则对象，包含匹配条件和动作

**支持的规则选项：**
- 基础：msg, sid, rev, priority
- 内容匹配：content, pcre, regex
- 流控制：flow, flowbits
- 协议字段：http_uri, dns_query等

### 6. Matchers（匹配器）

**职责：** 高效模式匹配

**引擎：**
- AC自动机：多模式匹配
- 正则表达式：PCRE支持
- Boyer-Moore：单模式快速匹配

### 7. Alerts（告警系统）

**职责：** 告警生成、去重和输出

**功能：**
- 告警生成：从规则匹配结果生成告警
- 去重：时间窗口内相同告警去重
- 多输出：控制台、文件（TEXT/JSON/CSV）、Syslog

### 8. Utils（工具层）

**PacketQueue:**
- 基于 `moodycamel::ConcurrentQueue`
- MPMC无锁队列
- 支持批量操作

**ThreadPool:**
- 通用线程池
- 任务队列和工作线程

## 数据流

### 单线程模式

```
PacketCapture → DetectionEngine.process_packet()
                      ↓
                1. Protocol Decoding (L2→L3→L4→L7)
                      ↓
                2. Flow Tracking
                      ↓
                3. Reassembly (TCP/IP)
                      ↓
                4. L7 Parsing (HTTP/DNS)
                      ↓
                5. Rule Matching
                      ↓
                6. Anomaly Detection
                      ↓
                7. Alert Generation
```

### 多线程模式

```
        PacketCapture Thread
                ↓
         [PacketQueue] (128K capacity)
           /    |    \
          /     |     \
    Worker1  Worker2  Worker3 ...
         \     |     /
          \    |    /
       ConcurrentFlowTable
           (256 shards)
```

## 编译产物

### 库文件（build/lib/）

- `libnetguardian_core.a`: 核心功能
- `libnetguardian_decoders.a`: 协议解码器
- `libnetguardian_flow.a`: 流管理
- `libreassembly.a`: 重组引擎
- `libnetguardian_rules.a`: 规则引擎
- `libalerts.a`: 告警系统
- `libnetguardian_utils.a`: 工具库

### 可执行文件（build/bin/）

**主程序：**
- `netguardian`: 完整的检测系统

**示例程序：**
- `example_basic_capture`: 基础捕获
- `example_decoder`: 协议解码
- `example_flow_tracking`: 流跟踪
- `example_tcp_reassembly`: TCP重组
- `example_http_parser`: HTTP解析
- `example_dns_parser`: DNS解析
- 等等...

## 清理和维护

### 清理构建产物

```bash
# 使用清理脚本
./scripts/clean.sh

# 或手动删除
rm -rf build/
```

### 重新构建

```bash
mkdir build && cd build
cmake ..
cmake --build . -j$(nproc)
```

### 运行测试

```bash
cd build
ctest --output-on-failure
```

## 依赖管理

### 系统依赖

- libpcap-dev: 数据包捕获
- pthread: 多线程支持
- CMake 3.15+: 构建系统

### 第三方库（third_party/）

- **concurrentqueue**: 高性能无锁队列
  - License: BSD-2-Clause / Boost Software License
  - 用途: 多线程数据包队列

## 代码规范

### 命名约定

- 类名：PascalCase (例如: `PacketCapture`)
- 函数名：snake_case (例如: `process_packet`)
- 成员变量：snake_case_ (例如: `packet_queue_`)
- 常量：UPPER_CASE (例如: `MAX_PACKET_SIZE`)

### 文件组织

- 头文件：`include/<module>/<name>.h`
- 源文件：`src/<module>/<name>.cpp`
- 测试文件：`tests/<module>/test_<name>.cpp`

### 包含顺序

1. 对应的头文件
2. C系统头文件
3. C++标准库头文件
4. 第三方库头文件
5. 项目头文件

## 性能考虑

### 单线程性能

- 吞吐量：~500 Mbps（小包场景）
- 延迟：<1ms（平均包处理时间）

### 多线程性能（6 workers）

- 吞吐量：~2.2 Gbps（理论4.4倍提升）
- 队列深度：128K packets
- 分片锁数量：256 shards

详见 [MULTITHREADING_OPTIMIZATION.md](MULTITHREADING_OPTIMIZATION.md)

## 文档更新

本文档应随项目演进保持更新。主要更新时机：

- 添加新模块
- 修改目录结构
- 更新依赖关系
- 性能基准变化

最后更新：2025-10-18
