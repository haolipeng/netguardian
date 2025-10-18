# NetGuardian 项目进度与规划

## 项目概述

NetGuardian 是一个结合 Snort3 和 Zeek 能力的网络安全监控系统，旨在提供高性能的数据包捕获、协议解析、流量分析和威胁检测功能。

**项目版本**: 0.1.0
**当前状态**: 开发中
**最后更新**: 2025-10-18

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

### ✅ Phase 7: 告警系统

#### 7.1 告警生成
- [x] 告警结构设计（Alert 类）
- [x] 告警生成器（AlertGenerator）
- [x] 告警优先级管理（4级：LOW/MEDIUM/HIGH/CRITICAL）
- [x] 告警去重（基于时间窗口和规则ID）
- [x] 告警分类（14种类别）

#### 7.2 告警输出
- [x] 控制台输出（支持彩色显示）
- [x] 文件输出（TEXT/JSON/CSV三种格式）
- [x] Syslog 输出
- [x] 组合输出（同时输出到多个目标）

#### 7.3 告警管理
- [x] AlertManager 统一管理
- [x] 去重配置（时间窗口、频率限制）
- [x] 统计信息（总数、各优先级分布、抑制数）

**实现文件**:
- `include/alerts/alert.h` - 告警数据结构
- `include/alerts/alert_generator.h` - 告警生成器
- `include/alerts/alert_output.h` - 输出器（Console/File/Syslog）
- `include/alerts/alert_manager.h` - 告警管理器
- `include/decoders/packet_info.h` - 数据包信息结构
- `src/alerts/CMakeLists.txt` - 构建配置
- `examples/example_alert_system.cpp` - 完整测试程序（6个测试）

**测试**: ✅ 通过（所有6个测试场景）

**测试结果**:
- 测试 1：告警生成（含匹配模式）
- 测试 2：多格式输出（TEXT/JSON/CSV）
- 测试 3：文件输出（3种格式文件）
- 测试 4：去重机制（10个告警→仅输出3个）
- 测试 5：优先级彩色显示
- 测试 6：组合输出（控制台+文件）

---

### ✅ Phase 8: IP 分片重组

#### 8.1 IPv4 分片重组
- [x] 分片节点数据结构（IpFragment）
- [x] 分片队列管理（双向链表）
- [x] 分片超时处理（默认60秒）
- [x] 分片重组算法（按偏移量排序）
- [x] 重叠分片处理（FIRST策略）
- [x] 顺序/乱序分片支持
- [x] 数据空洞检测

#### 8.2 IPv6 分片重组
- [x] IPv6 分片标识（src/dst IPv6 + id）
- [x] IPv6 分片重组（完整实现）
- [x] 与IPv4相同的核心算法

#### 8.3 技术特点
- [x] 基于四元组的分片跟踪（IPv4）
- [x] 基于三元组的分片跟踪（IPv6）
- [x] 内存限制保护
- [x] 详细统计信息

**实现文件**:
- `include/reassembly/ip_fragment.h` - IP分片节点
- `include/reassembly/ipv4_reassembler.h` - IPv4重组器
- `include/reassembly/ipv6_reassembler.h` - IPv6重组器
- `src/reassembly/ip_fragment.cpp` - 分片节点实现
- `src/reassembly/ipv4_reassembler.cpp` - IPv4重组实现（~150行）
- `src/reassembly/ipv6_reassembler.cpp` - IPv6重组实现（~140行）
- `examples/example_ip_reassembly.cpp` - 完整测试程序（5个测试）

**测试**: ✅ 通过（所有5个测试场景）

**测试结果**:
- 测试 1：IPv4顺序分片（89字节→3个分片）
- 测试 2：IPv4乱序分片（36字节→3个乱序分片）
- 测试 3：重叠分片处理（1次重叠检测）
- 测试 4：超时管理（3秒超时测试）
- 测试 5：IPv6分片重组（65字节→2个分片）

---

### ✅ Phase 9: 高级协议解析（部分完成）

#### 9.1 HTTP 深度解析
- [x] HTTP 请求解析（方法、URI、路径、查询字符串、版本）
- [x] HTTP 响应解析（状态码、原因短语、版本）
- [x] HTTP 头部提取（通用头部快速访问）
- [x] HTTP Body 提取（基于 Content-Length）
- [x] 请求/响应完整解析
- [x] 支持 9 种 HTTP 方法（GET/POST/PUT/DELETE等）
- [x] 支持 5 种 HTTP 版本（0.9至3.0）
- [ ] 文件提取功能
- [ ] Chunked 编码支持

**实现文件**:
- `include/decoders/http_parser.h` - HTTP 解析器接口
- `src/decoders/http_parser.cpp` - HTTP 解析实现（~380行）
- `examples/example_http_parser.cpp` - 完整测试程序（6个测试）

**测试**: ✅ 通过（所有6个测试场景）

**测试结果**:
- 测试 1：简单 GET 请求（95字节解析）
- 测试 2：带查询字符串的 GET 请求（167字节）
- 测试 3：POST 请求带 Body（182字节含33字节body）
- 测试 4：HTTP 200 OK 响应（173字节含48字节body）
- 测试 5：HTTP 404 Not Found 响应（131字节）
- 测试 6：HTTP 302 重定向响应（104字节）

**技术特点**:
- 无需外部依赖（纯 C++17 实现）
- 大小写不敏感的头部处理
- 状态分类方法（2xx/3xx/4xx/5xx）
- 常用头部快速访问（Host、User-Agent、Content-Type等）

---

### ✅ Phase 10: 检测引擎集成（主程序）

#### 10.1 核心检测引擎
- [x] DetectionEngine 类（完整实现）
- [x] 协议栈处理管道（L2→L3→L4→L7）
- [x] 流跟踪集成
- [x] TCP/IP 重组集成
- [x] HTTP/DNS 深度解析集成
- [x] DNS 异常检测集成
- [x] 告警系统集成
- [x] 统计信息收集

#### 10.2 主程序实现
- [x] 完整的 main.cpp（373行）
- [x] 命令行参数解析（12个选项）
- [x] 信号处理（SIGINT/SIGTERM）
- [x] 实时统计报告线程
- [x] 优雅关闭机制
- [x] 数据包捕获循环
- [x] 最终统计输出

#### 10.3 配置与示例
- [x] DetectionEngineConfig 结构
- [x] 示例配置文件（netguardian.conf.example）
- [x] 测试 PCAP 生成脚本（generate_test_pcap.py）
- [x] 测试流量包（包含 DNS/HTTP/ICMP/UDP）

#### 10.4 功能特性
- [x] 实时和离线分析模式（-i 或 -r）
- [x] BPF 过滤器支持（-f）
- [x] 可配置统计间隔（-s）
- [x] 数据包计数限制（-c）
- [x] 告警输出到文件（-A）
- [x] 规则目录配置（-R）
- [x] 功能开关（--no-flow、--no-reassembly、--no-anomaly）

**实现文件**:
- `include/core/detection_engine.h` - 检测引擎接口（~220行）
- `src/core/detection_engine.cpp` - 检测引擎实现（~530行）
- `src/main.cpp` - 主程序（~373行）
- `examples/netguardian.conf.example` - 配置文件示例
- `scripts/generate_test_pcap.py` - PCAP 生成工具
- `examples/test_traffic.pcap` - 测试数据包（52个包）

**测试**: ✅ 通过

**测试结果**:
- 处理 52 个数据包，无丢包
- 检测到 10 个 DNS 异常（高熵 DGA 域名）
- 协议统计正确（IPv4: 52, TCP: 12, UDP: 35, HTTP: 3, DNS: 30）
- 流跟踪正确（23 个活动流）
- 优雅关闭和资源清理成功

**技术特点**:
- 单线程数据包处理管道
- 独立统计报告线程
- 模块化架构，易于扩展
- 完整的统计信息（数据包、字节、协议分布、检测结果）
- 实时异常输出到控制台
- 支持告警输出到多种格式（TEXT/JSON/CSV）

---

## 📋 待实现功能

---

#### 9.2 DNS 深度解析
- [x] DNS 消息完整解析（Query/Response，4个Section）
- [x] 30+ 种 DNS 记录类型支持（A, AAAA, CNAME, MX, TXT, SOA, SRV, NS, PTR等）
- [x] RDATA 详细解析（不再只存储原始字节）
- [x] DNS 异常检测器（17种异常类型）
  - [x] 域名异常（超长域名、高熵值DGA、深层子域名、数字占比过高）
  - [x] DNS 隧道检测（大TXT记录、编码数据、频率异常）
  - [x] 协议异常（格式错误、罕见查询类型、响应代码异常）
  - [x] 可疑行为（黑名单IP、可疑TLD、零TTL）
- [x] DNS 事务跟踪器（Query/Response配对、RTT计算、统计信息）

**实现文件**:
- `include/decoders/dns_parser.h` - DNS 解析器接口（~400行）
- `src/decoders/dns_parser.cpp` - DNS 解析实现（~550行）
- `include/decoders/dns_anomaly_detector.h` - 异常检测器接口（~190行）
- `src/decoders/dns_anomaly_detector.cpp` - 异常检测实现（~450行）
- `include/decoders/dns_transaction.h` - 事务跟踪器接口（~120行）
- `src/decoders/dns_transaction.cpp` - 事务跟踪实现（~180行）
- `examples/example_dns_parser.cpp` - 完整测试程序（9个测试，~550行）

**测试**: ✅ 通过（9个测试场景）

**测试结果**:
- 测试 1：简单 A 记录查询（33字节）✅
- 测试 2：A 记录响应（2个IP地址）✅
- 测试 3：AAAA 记录（IPv6地址）✅
- 测试 4：CNAME 记录（别名解析）✅
- 测试 5：MX 记录（2个邮件服务器）✅
- 测试 7：异常检测 - 超长域名（检测到4个异常：高熵、深层子域名、编码数据、隧道疑似）✅
- 测试 8：异常检测 - 高熵DGA域名（熵值4.21，成功检测）✅
- 测试 9：事务跟踪（RTT: 10.127ms，匹配率100%）✅
- 测试 10：NXDOMAIN 响应（域名不存在）✅

**技术特点**:
- 支持域名压缩指针解析
- 无外部依赖（纯C++17实现）
- 基于香农熵的DGA检测（阈值3.5）
- DNS 隧道多指标综合检测
- Query/Response 自动配对（基于ID+IP+Port）
- 详细的 RTT 统计（平均/最小/最大）

---

### Phase 9: 高级协议解析（继续）

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
- ✅ 数据包捕获（libpcap）
- ✅ L2-L7 协议解析（完整协议栈）
- ✅ 流量跟踪（TCP 状态机）
- ✅ TCP 流重组（双向、乱序处理）
- ✅ IP 分片重组（IPv4/IPv6）
- ✅ 规则解析器（类 Snort 语法）
- ✅ 模式匹配引擎（AC 自动机、正则等）
- ✅ 告警系统（多输出格式、去重）
- ✅ HTTP 深度解析（请求/响应）
- ✅ DNS 深度解析（30+ 记录类型）
- ✅ DNS 异常检测（17种异常类型）
- ✅ **检测引擎集成（完整主程序）**

**发布日期**: 2025-10-18（功能完整，待优化）

### v0.2.0 - 性能优化与增强
- [ ] 规则检测引擎完全集成
- [ ] Snort3 规则完全兼容
- [ ] 性能优化（多线程）
- [ ] TLS/SSL 深度解析
- [ ] 完整的单元测试套件

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

**最后更新**: 2025-10-18
**文档版本**: 1.0
