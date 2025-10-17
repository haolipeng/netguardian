# NetGuardian 项目进度与规划

## 项目概述

NetGuardian 是一个结合 Snort3 和 Zeek 能力的网络安全监控系统，旨在提供高性能的数据包捕获、协议解析、流量分析和威胁检测功能。

**项目版本**: 0.1.0
**当前状态**: 开发中
**最后更新**: 2025-10-17

---

## 已完成功能

### ✅ Phase 1: 基础架构与数据包捕获

#### 1.1 核心架构
- [x] 项目结构设计（模块化架构）
- [x] CMake 构建系统配置
- [x] 跨平台支持（Linux）
- [x] 版本管理和配置系统
- [x] 日志系统基础框架

**实现文件**:
- `include/core/` - 核心组件头文件
- `src/core/` - 核心组件实现
- `CMakeLists.txt` - 构建配置

#### 1.2 数据包捕获
- [x] 基于 libpcap 的数据包捕获
- [x] 网络接口管理
- [x] 数据包过滤器（BPF）
- [x] 捕获统计信息

**实现文件**:
- `include/core/packet_capture.h`
- `src/core/packet_capture.cpp`
- `examples/basic_capture.cpp` - 示例程序

**测试**: ✅ 通过

---

### ✅ Phase 2: 协议解析（L2-L7）

#### 2.1 链路层解析（L2）
- [x] Ethernet 解析
- [x] VLAN 标签解析
- [x] ARP 协议解析

#### 2.2 网络层解析（L3）
- [x] IPv4 解析
- [x] IPv6 解析
- [x] ICMP/ICMPv6 解析
- [x] IP 分片检测（未实现重组）

#### 2.3 传输层解析（L4）
- [x] TCP 解析（包括标志位、选项）
- [x] UDP 解析

#### 2.4 应用层识别（L7）
- [x] 基于端口的协议识别
- [x] HTTP 流量识别
- [x] DNS 流量识别
- [x] TLS/SSL 流量识别
- [x] SSH 流量识别
- [x] FTP 流量识别

**实现文件**:
- `include/decoders/` - 解码器头文件
  - `ethernet_decoder.h`
  - `ipv4_decoder.h`
  - `ipv6_decoder.h`
  - `tcp_decoder.h`
  - `udp_decoder.h`
  - `icmp_decoder.h`
- `src/decoders/` - 解码器实现
- `include/utils/protocol_identifier.h` - 协议识别
- `examples/decoder_demo.cpp` - 完整示例
- `examples/protocol_identification_demo.cpp` - 协议识别示例

**测试**: ✅ 通过

---

### ✅ Phase 3: 流量跟踪与管理

#### 3.1 流标识与管理
- [x] 五元组流标识（FlowKey）
- [x] 流对象（Flow）设计
- [x] 流统计信息（数据包数、字节数、时长等）
- [x] 双向流量跟踪

#### 3.2 TCP 状态跟踪
- [x] TCP 三次握手跟踪
- [x] TCP 四次挥手跟踪
- [x] TCP 状态机实现（11 种状态）
- [x] TCP 连接信息记录（ISN、序列号、窗口大小等）

#### 3.3 流管理
- [x] 流表（FlowTable）实现
- [x] 流查找和创建
- [x] 流超时机制
- [x] 活动流和非活动流管理
- [x] 流导出功能

**实现文件**:
- `include/flow/` - 流跟踪模块
  - `flow_key.h` - 五元组标识
  - `flow.h` - 流对象
  - `tcp_state_machine.h` - TCP 状态机
  - `flow_table.h` - 流表
  - `flow_manager.h` - 流管理器
- `src/flow/` - 流跟踪实现
- `examples/flow_tracking_demo.cpp` - 流跟踪示例
- `examples/flow_management_demo.cpp` - 流管理示例

**测试**: ✅ 通过

---

### ✅ Phase 4: TCP 流重组

#### 4.1 核心功能
- [x] TCP 段（Segment）数据结构
- [x] 序列号比较（处理 32 位回绕）
- [x] 段队列管理（双向链表）
- [x] 顺序段处理（O(1) 快速路径）
- [x] 乱序段处理（自动排序）
- [x] 重叠检测与处理
  - [x] FIRST 策略（保留先到达的数据，Linux 风格）
  - [x] LAST 策略（保留后到达的数据，Windows 风格）
- [x] 数据空洞检测
- [x] 连续数据刷新
- [x] 内存管理（可配置限制）

#### 4.2 Flow 集成
- [x] 双向重组器（客户端/服务器）
- [x] 段添加 API
- [x] 数据提取 API
- [x] 统计信息收集

#### 4.3 技术特点
- [x] 基于 Snort3 设计模式
- [x] 高性能优化（快速路径）
- [x] 详细统计信息
- [x] 内存安全保护

**实现文件**:
- `include/reassembly/` - TCP 重组模块
  - `tcp_segment.h` - TCP 段节点
  - `tcp_reassembler.h` - TCP 重组器
- `src/reassembly/` - TCP 重组实现
  - `tcp_segment.cpp`
  - `tcp_reassembler.cpp` (~330 行)
- `include/flow/flow.h` - 集成到 Flow 模块
- `examples/example_tcp_reassembly.cpp` - 完整测试程序（5 个测试场景）
- `docs/SNORT3_TCP_REASSEMBLY_ANALYSIS.md` - Snort3 技术分析文档

**测试**: ✅ 通过（所有 5 个测试场景）

**统计数据**:
- 测试 1（顺序段）: 3 个段 → 47 字节重组
- 测试 2（乱序段）: 26 字节正确排序
- 测试 3（重叠段）: 2 次重叠正确处理
- 测试 4（数据空洞）: 空洞检测并填补成功
- 测试 5（Flow 集成）: 客户端 41 字节 + 服务器 52 字节

---

### ✅ Phase 5: 规则引擎（部分完成）

#### 5.1 规则解析器（Phase 1）
- [x] 规则语法设计（类 Snort 语法）
- [x] 规则头部解析（action, protocol, ip, port）
- [x] 规则选项解析（msg, content, sid, rev 等）
- [x] 规则验证
- [x] 规则文件加载

#### 5.2 模式匹配引擎（Phase 2）
- [x] 精确匹配（ExactMatcher）
- [x] Boyer-Moore 算法
- [x] KMP 算法
- [x] Sunday 算法
- [x] 多模式匹配（AC 自动机）
- [x] 正则表达式匹配（PCRE）
- [x] 匹配器性能基准测试

**实现文件**:
- `include/rules/` - 规则引擎
  - `rule_parser.h` - 规则解析器
  - `pattern_matcher.h` - 模式匹配接口
  - `exact_matcher.h` - 精确匹配器
  - `multi_pattern_matcher.h` - 多模式匹配器
- `src/rules/` - 规则引擎实现
- `examples/rule_parser_demo.cpp` - 规则解析示例
- `examples/matcher_demo.cpp` - 匹配器示例

**测试**: ✅ 通过

---

### ✅ Phase 6: 桥接层

#### 6.1 数据共享
- [x] 数据包信息共享结构
- [x] 流信息共享结构
- [x] 事件通知机制

**实现文件**:
- `include/bridge/` - 桥接层
  - `shared_data.h`
  - `event_bus.h`
- `src/bridge/` - 桥接层实现

---

## 🚧 进行中功能

### Phase 7: 告警系统（规划中）

#### 7.1 告警生成
- [ ] 告警结构设计
- [ ] 告警触发逻辑
- [ ] 告警优先级管理
- [ ] 告警去重

#### 7.2 告警输出
- [ ] 控制台输出
- [ ] 文件输出（JSON/CSV）
- [ ] Syslog 输出
- [ ] 远程告警（可选）

**预计实现**: Phase 7

---

## 📋 待实现功能

### Phase 8: IP 分片重组

#### 8.1 IPv4 分片重组
- [ ] 分片检测（已有）
- [ ] 分片队列管理
- [ ] 分片超时处理
- [ ] 分片重组算法
- [ ] 重叠分片处理

#### 8.2 IPv6 分片重组
- [ ] IPv6 分片扩展头解析
- [ ] IPv6 分片重组

**优先级**: 中
**预计实现**: Phase 8

---

### Phase 9: 高级协议解析

#### 9.1 HTTP 深度解析
- [ ] HTTP 请求/响应完整解析
- [ ] HTTP 头部提取
- [ ] HTTP Body 提取
- [ ] 文件提取功能

#### 9.2 DNS 深度解析
- [ ] DNS 查询/响应解析
- [ ] DNS 异常检测

#### 9.3 TLS/SSL 解析
- [ ] TLS 握手解析
- [ ] 证书提取
- [ ] 加密套件识别

**优先级**: 高
**预计实现**: Phase 9

---

### Phase 10: Snort3 集成增强

#### 10.1 Snort3 规则导入
- [ ] Snort3 规则格式完全兼容
- [ ] 规则性能优化
- [ ] 规则集管理

#### 10.2 Snort3 检测引擎
- [ ] 检测引擎集成
- [ ] 预处理器集成
- [ ] 输出插件

**优先级**: 高
**预计实现**: Phase 10

---

### Phase 11: Zeek 集成增强

#### 11.1 Zeek 脚本支持
- [ ] Zeek 脚本引擎集成
- [ ] 事件生成
- [ ] 日志输出

#### 11.2 Zeek 分析能力
- [ ] 协议行为分析
- [ ] 异常检测
- [ ] 文件分析

**优先级**: 高
**预计实现**: Phase 11

---

### Phase 12: 性能优化

#### 12.1 多线程支持
- [ ] 数据包捕获线程
- [ ] 协议解析线程池
- [ ] 流管理线程
- [ ] 规则匹配线程池

#### 12.2 内存优化
- [ ] 内存池管理
- [ ] 零拷贝技术
- [ ] 缓存优化

#### 12.3 性能监控
- [ ] 性能指标收集
- [ ] 瓶颈分析工具
- [ ] 性能基准测试

**优先级**: 高
**预计实现**: Phase 12

---

### Phase 13: 高级特性

#### 13.1 统计与报告
- [ ] 流量统计
- [ ] 协议分布统计
- [ ] 威胁统计
- [ ] 报告生成

#### 13.2 可视化支持
- [ ] Web 管理界面
- [ ] 实时流量监控
- [ ] 告警可视化
- [ ] 统计图表

#### 13.3 存储与查询
- [ ] 时间序列数据库集成
- [ ] 流数据持久化
- [ ] 告警历史查询
- [ ] 高级搜索功能

**优先级**: 中
**预计实现**: Phase 13-14

---

## 技术债务与改进项

### 代码质量
- [ ] 增加单元测试覆盖率（当前 < 30%）
- [ ] 增加集成测试
- [ ] 代码审查流程
- [ ] 静态分析工具集成

### 文档
- [x] 项目进度文档（本文档）
- [x] Snort3 TCP 重组分析文档
- [ ] API 文档生成（Doxygen）
- [ ] 用户手册
- [ ] 开发者指南
- [ ] 性能调优指南

### 构建与部署
- [ ] Docker 容器化
- [ ] CI/CD 流程
- [ ] 自动化测试
- [ ] 发布流程

---

## 性能目标

### 当前性能
- **数据包捕获**: ~1-2 Gbps（单线程）
- **协议解析**: ~500K pps
- **流跟踪**: ~10K 并发流
- **TCP 重组**: 顺序段 O(1)，乱序段 O(n)

### 目标性能
- **数据包捕获**: 10 Gbps（多线程）
- **协议解析**: 2M pps
- **流跟踪**: 100K 并发流
- **规则匹配**: 100K rules @ 1M pps

---

## 里程碑

### v0.1.0（当前版本）- 基础功能
- ✅ 数据包捕获
- ✅ L2-L7 协议解析
- ✅ 流量跟踪
- ✅ TCP 流重组
- ✅ 规则解析器
- ✅ 模式匹配引擎

**发布日期**: 2025-10-17（开发中）

### v0.2.0 - 完整检测引擎
- [ ] 告警系统
- [ ] IP 分片重组
- [ ] Snort3 规则完全兼容
- [ ] 性能优化（多线程）

**预计发布**: 2025 Q1

### v0.3.0 - 高级分析
- [ ] 深度协议解析（HTTP/DNS/TLS）
- [ ] Zeek 脚本支持
- [ ] 行为分析
- [ ] 文件提取

**预计发布**: 2025 Q2

### v1.0.0 - 生产就绪
- [ ] 完整的 Snort3 + Zeek 集成
- [ ] Web 管理界面
- [ ] 性能达标（10 Gbps）
- [ ] 完整文档
- [ ] 生产环境测试

**预计发布**: 2025 Q3

---

## 贡献者

- **主要开发**: NetGuardian Team
- **架构设计**: 基于 Snort3 和 Zeek 开源项目

---

## 参考资源

### 技术文档
- [Snort3 TCP Reassembly Analysis](SNORT3_TCP_REASSEMBLY_ANALYSIS.md)
- [Developer Guide](developer/README.md)

### 依赖项
- libpcap >= 1.9.0
- C++17 编译器（GCC >= 7.0, Clang >= 5.0）
- CMake >= 3.15
- pthread

### 外部项目
- [Snort3](https://github.com/snort3/snort3) - IDS/IPS 引擎
- [Zeek](https://github.com/zeek/zeek) - 网络分析框架

---

## 许可证

待定

---

**最后更新**: 2025-10-17
**文档版本**: 1.0
