# Snort3 TCP 流重组技术实现分析

## 一、核心架构

### 1.1 主要组件

Snort3 的 TCP 流重组功能由以下几个核心组件组成：

```
TcpReassembler (抽象基类)
    ├── TcpReassemblerIgnore (忽略重组)
    └── TcpReassemblerBase (基础重组器)
            ├── TcpReassemblySegments (段管理器)
            ├── TcpSegmentNode (段节点)
            ├── TcpOverlapResolver (重叠解决器)
            └── ProtocolAwareFlusher (PAF - 协议感知刷新)
```

### 1.2 关键文件

| 文件 | 作用 | 行数 |
|------|------|------|
| `tcp_reassembler.h/cc` | 重组器主类 | ~636 |
| `tcp_reassembly_segments.h/cc` | 段队列管理 | ~514 |
| `tcp_segment_node.h` | 段节点数据结构 | ~118 |
| `tcp_overlap_resolver.cc` | 处理重叠数据 | - |

---

## 二、核心数据结构

### 2.1 TcpSegmentNode - TCP 段节点

```cpp
class TcpSegmentNode {
    TcpSegmentNode* prev;           // 前一个段
    TcpSegmentNode* next;           // 后一个段

    struct timeval tv;              // 时间戳
    uint32_t ts;                    // TCP 时间戳选项

    uint32_t seq;                   // 段的初始序列号（固定）
    uint16_t length;                // 段数据的工作长度
    uint16_t offset;                // 段数据的起始偏移
    uint16_t cursor;                // 扫描位置（相对于 offset）
    uint16_t size;                  // 分配的负载大小
    uint8_t data[1];                // 实际数据（柔性数组）
};
```

**关键方法**：
- `start_seq()`: 返回 `seq + offset` (段的起始序列号)
- `next_seq()`: 返回 `start_seq() + length` (段的结束序列号)
- `scan_seq()`: 返回 `start_seq() + cursor` (扫描位置)
- `is_packet_missing()`: 检测是否有gap
- `next_no_gap()`: 检查下一个段是否连续

**设计亮点**：
- 使用 **struct hack** (柔性数组) 避免两次内存分配
- 字段按大小/对齐要求组织以最小化内存浪费
- `offset` 和 `cursor` 机制支持部分处理和重传检测

### 2.2 TcpReassemblySegments - 段队列管理器

```cpp
class TcpReassemblySegments {
    TcpSegmentNode* head = nullptr;     // 队列头
    TcpSegmentNode* tail = nullptr;     // 队列尾

    TcpSegmentNode* cur_rseg = nullptr; // 当前读取段
    TcpSegmentNode* cur_sseg = nullptr; // 当前扫描段

    uint32_t seg_count = 0;             // 当前队列段数
    uint32_t flush_count = 0;           // 已刷新段数

    uint32_t seglist_base_seq = 0;      // 第一个段的序列号
    uint32_t seg_bytes_total = 0;       // 当前队列总字节数
    uint32_t seg_bytes_logical = 0;     // 逻辑字节数（去除重叠）
    uint32_t total_bytes_queued = 0;    // 会话生命期总字节数
    uint32_t total_segs_queued = 0;     // 会话生命期总段数
    uint32_t overlap_count = 0;         // 遇到的重叠次数
};
```

**关键方法**：
- `queue_reassembly_segment()`: 将新段加入队列
- `add_reassembly_segment()`: 插入段（处理重叠）
- `purge_flushed_segments()`: 清除已刷新的段
- `skip_holes()`: 跳过数据空洞
- `advance_rcv_nxt()`: 推进接收窗口

---

## 三、核心算法

### 3.1 段队列插入算法

当新的 TCP 段到达时：

```
1. 检查段是否在窗口范围内 (segment_within_seglist_window)
2. 判断队列状态：
   - 空队列 → insert_segment_in_empty_seglist()
   - 非空队列 → insert_segment_in_seglist()
3. 处理重叠：
   - 检测新段与现有段的重叠
   - 根据重叠策略 (Overlap Policy) 决定保留哪部分数据
   - 更新统计信息 (overlap_count)
4. 维护双向链表：
   - 按序列号顺序插入
   - 更新 prev/next 指针
5. 更新队列统计：
   - seg_count, seg_bytes_total, seg_bytes_logical
```

### 3.2 快速路径 (Fast-track)

Snort3 对常见情况进行了优化：

```cpp
bool is_segment_fasttrack(TcpSegmentNode* tail, const TcpSegmentDescriptor& tsd) {
    // 如果新段正好接在队列末尾，无需遍历整个队列
    if (tail && SEQ_EQ(tail->next_seq(), tsd.get_seq())) {
        return true;
    }
    return false;
}
```

### 3.3 重叠处理策略 (Overlap Policy)

Snort3 支持多种重叠处理策略，模拟不同操作系统的行为：

- **OS_FIRST**: 保留先到达的数据（Linux, BSD风格）
- **OS_LAST**: 保留后到达的数据（Windows风格）
- **OS_LINUX**: Linux 特定策略
- **OS_OLD_LINUX**: 旧版 Linux
- **OS_BSD**: BSD 风格
- **OS_WINDOWS**: Windows 风格
- **OS_VISTA**: Windows Vista
- **OS_SOLARIS**: Solaris

这样可以规避基于操作系统差异的IDS逃避技术。

### 3.4 刷新 (Flush) 机制

```
Flush 的时机：
1. 数据连续且达到一定量时
2. 收到 ACK 确认时 (eval_flush_policy_on_ack)
3. 收到新数据时 (eval_flush_policy_on_data)
4. 连接关闭时 (FIN)
5. 非对称流检测 (eval_asymmetric_flush)

Flush 策略：
- STREAM_FLPOLICY_IGNORE: 忽略
- STREAM_FLPOLICY_ON_ACK: ACK 时刷新
- STREAM_FLPOLICY_ON_DATA: 收到数据时刷新
- Protocol-Aware (PAF): 协议感知刷新
```

---

## 四、协议感知刷新 (PAF)

### 4.1 PAF 的作用

PAF (Protocol-Aware Flushing) 是 Snort3 的重要特性：

- **问题**：传统方法按固定大小或 ACK 刷新，可能将一个应用层消息分割
- **解决**：根据应用层协议边界智能刷新
- **示例**：HTTP 请求在 `\r\n\r\n` 处刷新，DNS 在消息边界刷新

### 4.2 StreamSplitter

```cpp
class StreamSplitter {
    virtual StreamSplitter::Status scan(
        Packet*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp
    ) = 0;
};
```

不同协议有不同的 Splitter：
- `HttpSplitter`
- `DnsSplitter`
- `SmtpSplitter`
- `FtpSplitter`
- etc.

### 4.3 PAF 工作流程

```
1. 数据到达 → 添加到重组队列
2. 调用 splitter->scan() 分析数据
3. Splitter 返回：
   - FLUSH: 找到消息边界，返回刷新点
   - SEARCH: 继续搜索
   - SKIP: 跳过当前数据
   - ABORT: 中止扫描
4. 根据刷新点调用 flush_stream()
5. 将重组后的完整消息传递给检测引擎
```

---

## 五、内存管理

### 5.1 内存池 (Memory Pool)

Snort3 使用内存池管理段节点：

```cpp
static void TcpSegmentNode::setup() {
    // 预分配内存池
}

static TcpSegmentNode* create(const struct timeval& tv,
                               const uint8_t* segment,
                               uint16_t len) {
    // 从内存池分配
    size_t size = sizeof(TcpSegmentNode) + len - 1;
    TcpSegmentNode* node = (TcpSegmentNode*)malloc(size);
    // ...
}

void term() {
    // 释放回内存池
    free(this);
}
```

### 5.2 内存限制

```cpp
// 配置选项
max_bytes: 8388608  // 单个会话最大缓存 8MB
max_segs: 3072      // 最大段数
```

当超过限制时：
- 清除旧段 (purge_flushed_ackd)
- 强制刷新 (perform_partial_flush)
- 如果仍不够，丢弃新段并记录事件

---

## 六、关键优化技术

### 6.1 序列号比较宏

```cpp
#define SEQ_LT(a,b)  ((int32_t)((a) - (b)) < 0)
#define SEQ_LEQ(a,b) ((int32_t)((a) - (b)) <= 0)
#define SEQ_GT(a,b)  ((int32_t)((a) - (b)) > 0)
#define SEQ_GEQ(a,b) ((int32_t)((a) - (b)) >= 0)
#define SEQ_EQ(a,b)  ((int32_t)((a) - (b)) == 0)
```

这些宏正确处理 32 位序列号回绕问题。

### 6.2 快速路径检测

```cpp
// 最常见情况：按序到达的段
if (is_segment_fasttrack(tail, tsd)) {
    // 直接追加到队列末尾，O(1)
    add_reassembly_segment(...);
    return;
}
// 否则需要遍历查找插入位置，O(n)
```

### 6.3 延迟处理

- **Lazy evaluation**: 只在需要时才进行重组
- **Batch processing**: 积累多个段后一次性处理
- **Early drop**: 尽早丢弃无效数据

---

## 七、与 NetGuardian 的集成建议

### 7.1 可以直接借鉴的设计

1. **TcpSegmentNode 数据结构** - 完全可以复用
2. **段队列管理算法** - 双向链表 + 统计信息
3. **序列号比较宏** - 处理回绕
4. **重叠检测逻辑** - 算法可以简化后使用
5. **内存管理模式** - 内存池思想

### 7.2 简化方案（MVP）

对于 NetGuardian 的第一版 TCP 重组，建议：

```
1. 核心数据结构：
   - TcpSegmentNode (简化版)
   - TcpReassemblyQueue (段队列)

2. 基础功能：
   - 按序插入段
   - 简单的重叠处理（保留先到的）
   - 连续数据刷新

3. 暂不实现：
   - 多种重叠策略（只用 FIRST）
   - PAF 协议感知（后续扩展）
   - 复杂的内存管理（先用简单分配）
```

### 7.3 与现有 Flow 模块集成

```cpp
// 在现有的 Flow 类中添加
class Flow {
    // ... 现有成员 ...

    std::unique_ptr<TcpReassembler> client_reassembler_;
    std::unique_ptr<TcpReassembler> server_reassembler_;

    void process_tcp_segment(const Packet& packet, bool is_client);
    std::vector<uint8_t> get_reassembled_data(bool is_client);
};
```

### 7.4 API 设计建议

```cpp
class TcpReassembler {
public:
    // 添加新段
    void add_segment(uint32_t seq, const uint8_t* data, uint16_t len);

    // 获取已重组的连续数据
    bool get_reassembled_data(std::vector<uint8_t>& output, uint32_t& next_seq);

    // 清除已确认的数据
    void purge_acked_data(uint32_t ack_seq);

    // 获取统计信息
    ReassemblyStats get_stats() const;
};
```

---

## 八、实现优先级

### Phase 1: 基础重组 (MVP)
- ✅ TcpSegmentNode 数据结构
- ✅ 按序插入算法
- ✅ 简单重叠处理
- ✅ 基础刷新机制

### Phase 2: 增强功能
- ⬜ 多种重叠策略
- ⬜ 更好的内存管理
- ⬜ 性能优化（快速路径）

### Phase 3: 高级特性
- ⬜ PAF 协议感知刷新
- ⬜ 与规则引擎深度集成
- ⬜ 完整的统计和调试

---

## 九、性能考虑

### 9.1 时间复杂度

- **最佳情况** (按序到达): O(1) - 使用快速路径
- **最坏情况** (完全乱序): O(n) - 需要遍历队列
- **平均情况**: O(log n) - 可以考虑用红黑树优化

### 9.2 空间复杂度

- 每个段: ~40 bytes 开销 + 数据大小
- 典型会话: 100-1000 个段
- 内存上限: 可配置 (默认 8MB/会话)

### 9.3 优化建议

1. 使用内存池减少 malloc/free
2. 批量处理段
3. 及时清理已确认的数据
4. 限制最大队列长度

---

## 十、总结

Snort3 的 TCP 流重组是一个**成熟、高效、功能完整**的实现：

**优势**：
- ✅ 处理所有 TCP 异常情况（乱序、重传、重叠、分片）
- ✅ 支持多种操作系统语义（防规避）
- ✅ 协议感知刷新（PAF）
- ✅ 高性能优化（快速路径、内存池）

**复杂度**：
- 代码量大 (~1500+ 行)
- 依赖 Snort3 框架
- 配置选项多

**建议**：
对于 NetGuardian，可以**借鉴核心算法和数据结构**，但**从简单版本开始实现**，逐步增强功能。优先保证正确性，再优化性能。
