#ifndef NETGUARDIAN_UTILS_PACKET_QUEUE_H
#define NETGUARDIAN_UTILS_PACKET_QUEUE_H

#include "core/packet.h"
#include "concurrentqueue.h"
#include "blockingconcurrentqueue.h"
#include <cstddef>

namespace netguardian {
namespace utils {

/**
 * 高性能数据包队列（基于 moodycamel::ConcurrentQueue）
 *
 * 特点：
 * - 无锁设计，支持多生产者多消费者（MPMC）
 * - 高性能，针对缓存优化
 * - 支持批量操作
 */
class PacketQueue {
public:
    using Packet = core::Packet;

    /**
     * 构造函数
     * @param initial_capacity 初始容量
     */
    explicit PacketQueue(size_t initial_capacity = 65536)
        : queue_(initial_capacity)
    {}

    /**
     * 尝试入队一个数据包（非阻塞）
     * @param packet 要入队的数据包
     * @return true 成功, false 失败
     */
    bool try_enqueue(const Packet& packet) {
        return queue_.try_enqueue(packet);
    }

    /**
     * 尝试入队一个数据包（移动语义）
     */
    bool try_enqueue(Packet&& packet) {
        return queue_.try_enqueue(std::move(packet));
    }

    /**
     * 批量入队
     * @param packets 数据包数组
     * @param count 数量
     * @return 实际入队的数量
     */
    size_t try_enqueue_bulk(const Packet* packets, size_t count) {
        return queue_.try_enqueue_bulk(packets, count);
    }

    /**
     * 尝试出队一个数据包（非阻塞）
     * @param packet 输出参数，存储出队的数据包
     * @return true 成功, false 队列为空
     */
    bool try_dequeue(Packet& packet) {
        return queue_.try_dequeue(packet);
    }

    /**
     * 批量出队
     * @param packets 输出数组
     * @param max_count 最大出队数量
     * @return 实际出队的数量
     */
    size_t try_dequeue_bulk(Packet* packets, size_t max_count) {
        return queue_.try_dequeue_bulk(packets, max_count);
    }

    /**
     * 获取队列大小（近似值）
     */
    size_t size_approx() const {
        return queue_.size_approx();
    }

private:
    moodycamel::ConcurrentQueue<Packet> queue_;
};

/**
 * 阻塞式数据包队列
 * 支持阻塞等待操作
 */
class BlockingPacketQueue {
public:
    using Packet = core::Packet;

    /**
     * 构造函数
     * @param initial_capacity 初始容量
     */
    explicit BlockingPacketQueue(size_t initial_capacity = 65536)
        : queue_(initial_capacity)
    {}

    /**
     * 入队（非阻塞）
     */
    bool try_enqueue(const Packet& packet) {
        return queue_.try_enqueue(packet);
    }

    bool try_enqueue(Packet&& packet) {
        return queue_.try_enqueue(std::move(packet));
    }

    /**
     * 入队（阻塞，直到成功）
     */
    void enqueue(const Packet& packet) {
        queue_.enqueue(packet);
    }

    void enqueue(Packet&& packet) {
        queue_.enqueue(std::move(packet));
    }

    /**
     * 批量入队
     */
    size_t try_enqueue_bulk(const Packet* packets, size_t count) {
        return queue_.try_enqueue_bulk(packets, count);
    }

    /**
     * 出队（非阻塞）
     */
    bool try_dequeue(Packet& packet) {
        return queue_.try_dequeue(packet);
    }

    /**
     * 出队（阻塞，直到有数据）
     */
    void wait_dequeue(Packet& packet) {
        queue_.wait_dequeue(packet);
    }

    /**
     * 出队（带超时）
     * @param packet 输出参数
     * @param timeout_us 超时时间（微秒）
     * @return true 成功, false 超时
     */
    bool wait_dequeue_timed(Packet& packet, std::int64_t timeout_us) {
        return queue_.wait_dequeue_timed(packet, timeout_us);
    }

    /**
     * 批量出队
     */
    size_t try_dequeue_bulk(Packet* packets, size_t max_count) {
        return queue_.try_dequeue_bulk(packets, max_count);
    }

    /**
     * 批量出队（阻塞）
     */
    size_t wait_dequeue_bulk(Packet* packets, size_t max_count) {
        return queue_.wait_dequeue_bulk(packets, max_count);
    }

    /**
     * 获取队列大小（近似值）
     */
    size_t size_approx() const {
        return queue_.size_approx();
    }

private:
    moodycamel::BlockingConcurrentQueue<Packet> queue_;
};

} // namespace utils
} // namespace netguardian

#endif // NETGUARDIAN_UTILS_PACKET_QUEUE_H
