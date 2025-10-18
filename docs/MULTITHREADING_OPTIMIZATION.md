# NetGuardian 多线程性能优化设计文档

## 概述

本文档描述了 NetGuardian 项目的多线程性能优化方案，目标是通过并行处理提升数据包处理吞吐量。

## 架构设计

### 整体架构

```
┌────────────────┐
│  Capture Thread│  (主线程)
│   (libpcap)    │
└───────┬────────┘
        │ enqueue()
        ▼
┌────────────────────────────────┐
│  Lock-free Packet Queue        │
│  (moodycamel::ConcurrentQueue) │
│  容量: 128K packets             │
└────────┬───────────────────────┘
         │ dequeue()
         ▼
┌─────────────────────────────────┐
│    Worker Thread Pool           │
│  ┌──────┐ ┌──────┐ ┌──────┐   │
│  │Worker│ │Worker│ │Worker│...│
│  │  0   │ │  1   │ │  2   │   │
│  └──────┘ └──────┘ └──────┘   │
└─────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  Concurrent Flow Table          │
│  (256 shards with shared_mutex) │
└─────────────────────────────────┘
```

### 关键组件

#### 1. 无锁队列 (Lock-free Queue)

使用 **moodycamel::ConcurrentQueue**，高性能 MPMC（Multi-Producer Multi-Consumer）无锁队列：

**特点：**
- 无锁设计，避免线程竞争
- 支持批量操作（bulk enqueue/dequeue）
- 针对缓存友好优化
- 单个元素操作复杂度 O(1)

**实现文件：**
- `include/utils/packet_queue.h`

**使用示例：**
```cpp
utils::PacketQueue queue(131072);  // 128K capacity

// 捕获线程
queue.try_enqueue(packet);

// 工作线程
Packet pkt;
if (queue.try_dequeue(pkt)) {
    process_packet(pkt);
}
```

#### 2. 并发流表 (Concurrent Flow Table)

使用**分片锁（Sharded Locking）**技术优化并发访问：

**设计思路：**
- 将哈希表分成 N 个shard（默认256个）
- 每个shard有独立的 `shared_mutex`
- 使用 FlowKey 的哈希值分配到对应 shard
- 读操作使用共享锁（`shared_lock`），多个线程可并发读
- 写操作使用独占锁（`unique_lock`），保证线程安全

**优势：**
- 大幅减少锁竞争
- 256个shard理论上可支持256倍并发
- 不同流的操作完全并行

**实现文件：**
- `include/flow/concurrent_flow_table.h`

**核心代码：**
```cpp
class ConcurrentFlowTable {
private:
    struct Shard {
        mutable std::shared_mutex mutex;
        std::unordered_map<FlowKey, FlowPtr> flows;
        FlowTableStats stats{};
    };

    std::vector<Shard> shards_;  // 256 shards

    size_t get_shard_index(const FlowKey& key) const {
        size_t hash = std::hash<FlowKey>{}(key);
        return hash & (num_shards_ - 1);  // Fast modulo
    }
};
```

#### 3. 工作线程池

**每个工作线程独立拥有：**
- 协议解码器（Ethernet, IPv4, TCP, UDP等）
- L7解析器（HTTP, DNS）
- 重组引擎（TCP, IP）
- DNS异常检测器
- 局部统计计数器

**优势：**
- 避免共享组件的锁竞争
- 减少缓存失效（cache-line bouncing）
- 局部统计最后汇总，减少原子操作

**实现文件：**
- `include/core/mt_detection_engine.h`
- `src/core/mt_detection_engine.cpp`

#### 4. 线程池

简单的通用线程池实现（可选组件）：

**实现文件：**
- `include/utils/thread_pool.h`

## 配置选项

```cpp
struct MTDetectionEngineConfig {
    // 线程配置
    size_t num_worker_threads = 0;    // 0 = auto (CPU cores - 1)
    size_t queue_size = 131072;       // 128K packets
    size_t flow_table_shards = 256;   // Flow table shards

    // 性能调优
    size_t batch_size = 32;            // Batch processing size
    bool enable_batching = true;       // Enable batch mode
    bool enable_cpu_affinity = false;  // Pin threads to CPUs
};
```

## 性能优化技术

### 1. 批处理 (Batching)

工作线程一次从队列取出多个数据包处理，减少队列操作开销：

```cpp
std::vector<Packet> batch;
batch.reserve(32);

for (size_t i = 0; i < 32; ++i) {
    Packet pkt;
    if (queue.try_dequeue(pkt)) {
        batch.push_back(std::move(pkt));
    }
}

process_batch(batch);
```

### 2. 局部统计 (Per-Worker Stats)

每个工作线程维护局部统计，避免原子操作开销：

```cpp
struct PerWorkerComponents {
    DetectionEngineStats local_stats{};  // 非原子
};

// 最后汇总
DetectionEngineStats get_stats() const {
    DetectionEngineStats total{};
    for (const auto& comp : worker_components_) {
        total += comp.local_stats;
    }
    return total;
}
```

### 3. 避免False Sharing

使用 `alignas(64)` 确保原子变量在独立缓存行：

```cpp
alignas(64) std::atomic<uint64_t> total_packets_{0};
alignas(64) std::atomic<uint64_t> total_bytes_{0};
alignas(64) std::atomic<uint64_t> dropped_packets_{0};
```

### 4. CPU 亲和性 (可选)

将线程绑定到特定CPU核心，提升缓存命中率：

```cpp
// Linux specific
cpu_set_t cpuset;
CPU_ZERO(&cpuset);
CPU_SET(core_id, &cpuset);
pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
```

## 性能对比

### 预期性能提升

假设测试环境：
- CPU: 8核心
- 数据包大小: 平均 512 bytes
- 协议分布: 80% TCP, 20% UDP

| 配置 | 吞吐量（估算） | 提升倍数 |
|------|---------------|---------|
| 单线程 | ~500 Mbps | 1x |
| 2工作线程 | ~900 Mbps | 1.8x |
| 4工作线程 | ~1.6 Gbps | 3.2x |
| 6工作线程 | ~2.2 Gbps | 4.4x |

### 性能测试工具

计划创建的基准测试工具：

1. **pcap_replay_benchmark** - PCAP文件回放测试
   - 支持单线程/多线程对比
   - 测量吞吐量（pps, Mbps）
   - CPU使用率监控
   - 队列深度统计

2. **synthetic_traffic_benchmark** - 合成流量测试
   - 生成指定速率的数据包
   - 测试极限吞吐量
   - 压力测试

## 待完成工作

### 代码完善

- [ ] 修复 FlowTableStats 结构体（添加缺失字段）
- [ ] 修复 Flow 类接口（添加缺失方法）
- [ ] 修复 DetectionEngineStats（移除atomic成员或改为load()）
- [ ] 修复 MTDetectionEngineConfig（添加缺失字段）
- [ ] 修复各种API调用不匹配

### 性能测试

- [ ] 创建性能基准测试工具
- [ ] 单线程 vs 多线程性能对比
- [ ] 不同线程数的扩展性测试
- [ ] 不同队列大小的影响
- [ ] 不同batch size的影响
- [ ] CPU亲和性的效果测试

### 文档

- [ ] 性能调优指南
- [ ] 最佳配置建议
- [ ] 性能分析报告

## 技术参考

### 使用的开源库

1. **moodycamel::ConcurrentQueue**
   - GitHub: https://github.com/cameron314/concurrentqueue
   - License: BSD-2-Clause or Boost Software License
   - 特点：工业级无锁队列，被广泛使用

### 相关论文

1. **分片锁技术**
   - "The Art of Multiprocessor Programming" - Maurice Herlihy

2. **无锁数据结构**
   - "Simple, Fast, and Practical Non-Blocking and Blocking Concurrent Queue Algorithms" - Michael & Scott

### 类似项目参考

1. **Suricata IDS** - 多线程IDS/IPS
   - 使用工作线程池 + 无锁队列
   - 支持GPU加速

2. **DPDK** - 数据平面开发套件
   - 无锁环形缓冲区（Ring）
   - CPU亲和性优化

## 总结

NetGuardian的多线程优化采用了现代并发编程的最佳实践：

✅ **无锁队列** - 消除线程间等待
✅ **分片锁** - 最小化锁粒度
✅ **批处理** - 提升吞吐量
✅ **局部化** - 减少共享状态
✅ **缓存友好** - 避免false sharing

理论上可实现接近线性的性能扩展（在CPU核心数量范围内）。

## 下一步

1. 修复当前编译错误
2. 完成基准测试工具
3. 进行实际性能测试
4. 根据测试结果优化参数
5. 撰写性能报告
