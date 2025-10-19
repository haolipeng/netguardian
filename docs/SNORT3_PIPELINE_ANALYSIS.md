# Snort3 数据包处理流水线架构分析

## 概述

Snort3 采用了**高度模块化的 Inspector 框架**，将数据包处理组织成**5 个主要阶段**的流水线，每个阶段由不同类型的 Inspector 组成。这种设计实现了灵活的扩展性和清晰的职责分离。

---

## 核心架构图

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Snort3 数据包处理流水线                              │
└─────────────────────────────────────────────────────────────────────┘

DAQ Instance (网络/PCAP 数据包采集)
        │
        ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Analyzer::process_messages() - 批量接收 DAQ 消息                      │
└─────────────────────────────────────────────────────────────────────┘
        │
        ▼ 遍历每个消息
┌─────────────────────────────────────────────────────────────────────┐
│  Analyzer::process_daq_pkt_msg() - 处理单个数据包消息                   │
└─────────────────────────────────────────────────────────────────────┘
        │
        ▼
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  阶段 1: DECODE (协议解码)                                           ┃
┃  Entry: PacketManager::decode()                                    ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    │
    ├─ 解析以太网头
    ├─ 解析 IP 头 (IPv4/IPv6)
    ├─ 解析传输层头 (TCP/UDP/ICMP)
    ├─ 构建数据包层结构
    └─ 设置数据包类型 (PktType)
        │
        ▼
┌─────────────────────────────────────────────────────────────────────┐
│  process_packet() + main_hook                                       │
│  进入检测引擎                                                          │
└─────────────────────────────────────────────────────────────────────┘
        │
        ▼
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  阶段 2: INSPECTION (检查/预处理)                                     ┃
┃  Entry: DetectionEngine::inspect() → InspectorManager::execute()   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    │
    ├─ InspectorManager::probe_first()
    │  └─ IT_PROBE_FIRST 类型 Inspector
    │
    ├─ InspectorManager::execute() - 按顺序执行：
    │  │
    │  ├─ IT_PACKET Inspectors
    │  │  └─ 原始数据包处理 (normalize, capture)
    │  │
    │  ├─ IT_STREAM Inspectors
    │  │  └─ 流跟踪 & 重组 (TCP/UDP/IP 流)
    │  │
    │  ├─ IT_FIRST Inspectors
    │  │  └─ 首包分析
    │  │
    │  ├─ IT_NETWORK Inspectors
    │  │  └─ 网络层处理 (ARP, BO 检测)
    │  │
    │  ├─ IT_SERVICE Inspectors
    │  │  └─ 应用层检查 (HTTP, DNS, SSL, SMB, FTP, etc.)
    │  │
    │  └─ IT_CONTROL Inspectors
    │     └─ 检测前控制 (AppID)
    │
    ▼
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  阶段 3: DETECTION (规则检测)                                         ┃
┃  Entry: DetectionEngine::detect()                                  ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    │
    ├─ fp_full() - 快速模式匹配
    ├─ 规则评估
    ├─ 事件队列处理
    └─ 异步检测卸载 (如果启用)
        │
        ▼
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  阶段 4: POST-DETECTION PROBING (检测后探测)                         ┃
┃  Entry: InspectorManager::probe()                                  ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    │
    └─ IT_PROBE Inspectors
       └─ 性能监控、端口扫描检测等
        │
        ▼
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  阶段 5: LOGGING & VERDICT (日志 & 裁决)                             ┃
┃  Entry: Analyzer::post_process_daq_pkt_msg()                       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    │
    ├─ distill_verdict() - 确定最终动作
    │  └─ PASS, BLOCK, WHITELIST, BLACKLIST, IGNORE, REPLACE
    │
    ├─ EventManager::call_loggers() - 调用日志模块
    │
    └─ finalize_message() - 发送裁决到 DAQ
        │
        ▼
    DAQ Verdict (数据包最终处理结果)
```

---

## 详细架构分析

### 1. 主入口点：Analyzer 类

**文件：** `src/main/analyzer.cc`

Analyzer 是 Snort3 的核心数据包处理线程，负责从 DAQ 获取数据包并驱动整个流水线。

```cpp
// 主循环
void Analyzer::analyze()
{
    while (!exit_requested)
    {
        // 批量接收 DAQ 消息
        DAQ_RecvStatus rstat = process_messages();

        // 处理各种状态
        if (rstat != DAQ_RSTAT_OK && rstat != DAQ_RSTAT_WOULD_BLOCK)
        {
            // 处理超时、中断、EOF 等
        }
    }
}

// 批量处理消息
DAQ_RecvStatus Analyzer::process_messages()
{
    // 接收一批 DAQ 消息
    unsigned num_recv = DAQ_BATCH_SIZE;
    DAQ_RecvStatus rstat = daq_instance->receive_messages(&num_recv);

    // 遍历处理每个消息
    for (unsigned i = 0; i < num_recv; i++)
    {
        process_daq_msg(msgs[i]);
    }

    return rstat;
}

// 路由不同类型的消息
void Analyzer::process_daq_msg(const DAQ_Msg_t* msg)
{
    switch (msg->type)
    {
        case DAQ_MSG_TYPE_PACKET:
            process_daq_pkt_msg(msg);  // 数据包消息
            break;
        case DAQ_MSG_TYPE_SOF:
            // Start of Flow
            break;
        case DAQ_MSG_TYPE_EOF:
            // End of Flow
            break;
        // ... 其他消息类型
    }
}
```

---

### 2. Inspector 框架：核心抽象

**文件：** `src/framework/inspector.h`

Inspector 是 Snort3 中所有处理模块的基类，提供了统一的接口。

#### Inspector 基类

```cpp
class Inspector
{
public:
    // ═════════════════════════════════════════════════════════
    // 配置阶段（启动时）
    // ═════════════════════════════════════════════════════════

    virtual bool configure(SnortConfig*) { return true; }
    virtual void tear_down(SnortConfig*) { }
    virtual bool disable(SnortConfig*) { return false; }

    // ═════════════════════════════════════════════════════════
    // 线程本地初始化（每个数据包处理线程）
    // ═════════════════════════════════════════════════════════

    virtual void tinit() { }   // 分配线程本地资源
    virtual void tterm() { }   // 清理

    // ═════════════════════════════════════════════════════════
    // 数据包处理（热路径）
    // ═════════════════════════════════════════════════════════

    virtual bool likes(Packet*);              // 过滤数据包
    virtual void eval(Packet*) { }            // 处理数据包
    virtual void clear(Packet*) { }           // 释放线程本地数据

    // ═════════════════════════════════════════════════════════
    // 检查缓冲区（供规则检测使用）
    // ═════════════════════════════════════════════════════════

    virtual bool get_buf(InspectionBuffer::Type, Packet*, InspectionBuffer&);
    virtual bool get_buf(const char* key, Packet*, InspectionBuffer&);
};
```

#### Inspector 类型枚举

```cpp
enum InspectorType
{
    IT_PASSIVE,      // 仅配置，数据消费者
    IT_WIZARD,       // 服务识别
    IT_PACKET,       // 原始数据包处理（normalize, capture）
    IT_STREAM,       // 流跟踪 & 重组
    IT_FIRST,        // 首包分析
    IT_NETWORK,      // 网络层（ARP, BO 检测）
    IT_SERVICE,      // 应用层（HTTP, DNS, SSL, SMB 等）
    IT_CONTROL,      // 检测前控制（AppID）
    IT_PROBE,        // 检测后探测（性能监控、端口扫描）
    IT_FILE,         // 文件识别
    IT_PROBE_FIRST,  // 检测前探测
    IT_MAX
};
```

#### Inspector API 结构

```cpp
struct InspectApi
{
    BaseApi base;
    InspectorType type;         // Inspector 类型
    uint32_t proto_bits;        // 支持的协议位掩码

    const char** buffers;       // 导出的检查缓冲区
    const char* service;        // 服务名称（IT_SERVICE 用）

    InspectFunc pinit;          // 插件初始化
    InspectFunc pterm;          // 插件清理
    InspectFunc tinit;          // 线程本地初始化
    InspectFunc tterm;          // 线程本地清理
    InspectNew ctor;            // 创建 Inspector 实例
    InspectDelFunc dtor;        // 删除实例
    InspectSsnFunc ssn;         // 获取会话跟踪器
    InspectFunc reset;          // 重置统计
};
```

---

### 3. 流水线各阶段详解

#### 阶段 1: DECODE（协议解码）

**入口：** `PacketManager::decode()`
**文件：** `src/protocols/packet_manager.h`

```cpp
void PacketManager::decode(
    Packet* p,
    const DAQ_PktHdr_t* pkthdr,
    const uint8_t* data,
    uint32_t data_len,
    bool daq_injected,
    int retry)
{
    // 1. 设置数据包基本信息
    p->pkth = pkthdr;
    p->pkt = data;
    p->pktlen = data_len;

    // 2. 基于 datalink 类型选择解码器
    const CodecData& cd = codec_data[pkthdr->datalink_type];

    // 3. 调用 Codec 链进行解码
    cd.codec->decode(p, data, data_len, cd);

    // 4. 构建协议栈信息
    // - 以太网 → IP → TCP/UDP → 应用层
    // - 填充 p->ptrs (协议指针结构)

    // 5. 设置数据包类型
    set_packet_type(p);
}
```

**Codec 链式解码：**
```
Codec::eth → Codec::ipv4 → Codec::tcp → Codec::http
```

#### 阶段 2: INSPECTION（检查/预处理）

**入口：** `DetectionEngine::inspect()`
**文件：** `src/detection/detection_engine.cc`

```cpp
bool DetectionEngine::inspect(Packet* p)
{
    bool inspected = false;

    // 2.1 预检测探测
    InspectorManager::probe_first(p);

    if ( !(p->ptrs.decode_flags & DECODE_ERR_FLAGS) )
    {
        enable_content(p);

        // 2.2 主检查流水线（按类型顺序执行）
        InspectorManager::execute(p);

        inspected = true;

        // 2.3 检测阶段（下一阶段）
        if ( !all_disabled(p) )
        {
            if ( detect(p, offload_enabled) )
                return false;  // 卸载的数据包
        }

        // 2.4 更新流的检查时长
        if ( p->flow )
            p->flow->add_inspection_duration(...);
    }

    finish_inspect_with_latency(p);
    return inspected;
}
```

**Inspector 执行顺序：**

```cpp
// InspectorManager::execute() 内部按此顺序执行：

void InspectorManager::execute(Packet* p)
{
    // 1. IT_PACKET: 原始数据包处理
    for (auto* inspector : packet_inspectors)
    {
        inspector->eval(p);
    }

    // 2. IT_STREAM: 流跟踪和重组
    for (auto* inspector : stream_inspectors)
    {
        inspector->eval(p);  // TCP 重组、UDP 会话等
    }

    // 3. IT_FIRST: 首包分析
    for (auto* inspector : first_inspectors)
    {
        inspector->eval(p);
    }

    // 4. IT_NETWORK: 网络层检查
    for (auto* inspector : network_inspectors)
    {
        inspector->eval(p);
    }

    // 5. IT_SERVICE: 应用层检查（最重要）
    for (auto* inspector : service_inspectors)
    {
        if (inspector->likes(p))  // 协议匹配
        {
            inspector->eval(p);   // HTTP, DNS, SSL 等
        }
    }

    // 6. IT_CONTROL: 检测前控制
    for (auto* inspector : control_inspectors)
    {
        inspector->eval(p);  // AppID 等
    }
}
```

**典型的 IT_SERVICE Inspector：**
```
- http_inspect: HTTP 协议解析和规范化
- dns: DNS 协议解析
- ssl: SSL/TLS 握手分析
- smtp: 邮件协议检查
- ftp_server, ftp_client: FTP 协议
- ssh: SSH 协议分析
```

#### 阶段 3: DETECTION（规则检测）

**入口：** `DetectionEngine::detect()`
**文件：** `src/detection/detection_engine.cc`

```cpp
bool DetectionEngine::detect(Packet* p, bool offload_enabled)
{
    // 3.1 快速模式匹配（核心性能路径）
    int result = fp_full(p, offload_enabled);

    if (result == 1)
    {
        // 异步检测卸载
        return true;
    }

    // 3.2 处理事件队列
    // 规则匹配后，事件被加入队列
    // 根据优先级排序和过滤

    // 3.3 日志记录准备
    // 为下一阶段准备日志数据

    return false;
}
```

**快速模式匹配流程：**
```
fp_full(Packet* p)
  │
  ├─ 提取检查缓冲区
  │  └─ http_uri, http_header, raw_data 等
  │
  ├─ 使用 AC（Aho-Corasick）算法
  │  └─ 多模式匹配，查找所有可能匹配的规则
  │
  ├─ 对匹配的规则进行完整评估
  │  └─ 检查所有规则选项（content, pcre, byte_test 等）
  │
  └─ 将触发的规则加入事件队列
```

#### 阶段 4: POST-DETECTION PROBING（检测后探测）

**入口：** `InspectorManager::probe()`

```cpp
void InspectorManager::probe(Packet* p)
{
    // 执行 IT_PROBE 类型的 Inspector
    for (auto* inspector : probe_inspectors)
    {
        inspector->eval(p);
    }
}
```

**典型的 IT_PROBE Inspector：**
- `perf_monitor`: 性能统计和监控
- `port_scan`: 端口扫描检测
- `rate_filter`: 速率限制

#### 阶段 5: LOGGING & VERDICT（日志 & 裁决）

**入口：** `Analyzer::post_process_daq_pkt_msg()`
**文件：** `src/main/analyzer.cc`

```cpp
void Analyzer::post_process_daq_pkt_msg(Packet* p)
{
    // 5.1 确定最终裁决
    DAQ_Verdict verdict = distill_verdict(p);

    // 5.2 发布终结事件（如果有订阅者）
    if (p->flow && p->flow->flags.trigger_finalize_event)
    {
        FinalizePacketEvent event(p, verdict);
        DataBus::publish(intrinsic_pub_id,
                        IntrinsicEventIds::FINALIZE_PACKET, event);
    }

    // 5.3 调用日志记录器
    if (verdict != MAX_DAQ_VERDICT)
    {
        EventManager::call_loggers(p, verdict);
    }

    // 5.4 将裁决发送回 DAQ
    p->daq_instance->finalize_message(p->daq_msg, verdict);
}
```

**Verdict 类型：**
```cpp
typedef enum {
    DAQ_VERDICT_PASS,       // 放行
    DAQ_VERDICT_BLOCK,      // 阻断
    DAQ_VERDICT_REPLACE,    // 替换（修改数据包内容）
    DAQ_VERDICT_WHITELIST,  // 白名单（信任流）
    DAQ_VERDICT_BLACKLIST,  // 黑名单（拒绝流）
    DAQ_VERDICT_IGNORE,     // 忽略（不再检查此流）
    DAQ_VERDICT_RETRY,      // 重试
    MAX_DAQ_VERDICT
} DAQ_Verdict;
```

---

## 4. 上下文管理

Snort3 使用 `IpsContext` 来管理单个数据包的所有检测状态。

**文件：** `src/detection/ips_context.h`

```cpp
class IpsContext
{
public:
    Packet* packet;              // 当前处理的数据包
    SF_EVENTQ* event_queue;      // 匹配的事件队列

    // 上下文数据管理（Inspector 私有数据）
    void set_context_data(unsigned id, IpsContextData*);
    IpsContextData* get_context_data(unsigned id) const;

    // 控制检测行为
    void disable_detection();
    void disable_inspection();

    // 回调注册
    void register_post_callback(Callback callback);

private:
    std::vector<IpsContextData*> context_data;
};
```

**上下文切换器：** `ContextSwitcher`

```cpp
class ContextSwitcher
{
public:
    void start();               // 激活线程数据包的上下文
    void stop();                // 释放上下文

    IpsContext* interrupt();    // 激活伪数据包上下文
    IpsContext* complete();     // 完成伪数据包处理

    void suspend();             // 暂停当前，激活先前
    void resume(IpsContext*);   // 恢复暂停的上下文
};
```

---

## 5. 关键文件总结

| 文件路径 | 职责 |
|---------|------|
| `src/main/analyzer.h` | 主数据包处理线程编排器 |
| `src/main/analyzer.cc` | 数据包循环、DAQ 消息处理 |
| `src/framework/inspector.h` | Inspector 基类 & API |
| `src/managers/inspector_manager.h` | Inspector 生命周期 & 执行 |
| `src/detection/detection_engine.h` | 检测编排 |
| `src/detection/detection_engine.cc` | 检查 & 检测流水线 |
| `src/protocols/packet_manager.h` | 数据包解码 & 编码 |
| `src/detection/context_switcher.h` | 上下文管理 |
| `src/detection/ips_context.h` | 检测状态持有者 |
| `src/detection/detect.h` | 日志回调 |

---

## 6. 与 NetGuardian Pipeline 的对比

| 维度 | Snort3 | NetGuardian (当前) |
|------|--------|-------------------|
| **抽象层次** | Inspector 框架 | PacketProcessor 接口 |
| **流水线组织** | 按 InspectorType 分类 | 手动顺序添加 Processor |
| **扩展性** | 插件式，动态加载 | 编译时静态链接 |
| **阶段划分** | 5 个固定阶段 | 灵活的 Processor 链 |
| **上下文管理** | IpsContext + ContextSwitcher | PacketContext |
| **伪数据包处理** | 支持（用于重组后的流） | 部分支持 |
| **检测引擎** | 集成在流水线中 | 作为独立 Processor |

---

## 7. 对 NetGuardian 的启示

### 可借鉴的设计

1. **Inspector Type 分类**
   - 可以为 PacketProcessor 引入类型枚举
   - 按类型自动排序和组织流水线

2. **上下文切换机制**
   - 支持伪数据包（重组后的数据）处理
   - 暂停/恢复上下文（用于异步处理）

3. **Inspector API 标准化**
   - 统一的生命周期接口
   - 检查缓冲区导出机制

4. **日志模块解耦**
   - Snort3 的 EventManager 独立于检测引擎
   - 支持多种日志输出格式

### NetGuardian 的优势

1. **更简洁的设计**
   - PacketPipeline 概念更直观
   - 无需复杂的类型系统

2. **现代 C++ 实践**
   - `std::unique_ptr` 管理所有权
   - 更好的 RAII 模式

3. **清晰的职责分离**
   - Pipeline 只做编排
   - 检测作为一个 Processor

---

## 总结

Snort3 的流水线架构展示了**高度模块化**的设计理念：

✅ **Inspector 框架**：统一的扩展接口
✅ **类型驱动**：按 InspectorType 自动组织流水线
✅ **阶段清晰**：5 个固定阶段，职责明确
✅ **上下文管理**：支持复杂的数据包和伪数据包处理
✅ **插件化**：运行时动态加载模块

NetGuardian 可以在保持简洁性的同时，借鉴 Snort3 的：
- Inspector 类型分类思想
- 上下文切换机制
- 标准化的 API 接口

但 NetGuardian 的 **PacketPipeline** 命名和设计理念更加直观和现代！
