#ifndef NETGUARDIAN_CORE_PACKET_CONTEXT_H
#define NETGUARDIAN_CORE_PACKET_CONTEXT_H

#include "core/packet.h"
#include "flow/flow.h"
#include "decoders/http_parser.h"
#include "decoders/dns_parser.h"
#include <memory>
#include "utils/any.h"
#include <unordered_map>
#include <string>

namespace netguardian {
namespace core {

// 前向声明
class StatisticsCollector;

/**
 * PacketContext - 数据包处理上下文
 *
 * 这个类在处理管道中传递，携带：
 * 1. 原始数据包
 * 2. 解析后的信息（流、HTTP/DNS 消息等）
 * 3. 处理状态（是否应该丢弃等）
 * 4. 统计收集器引用
 * 5. 自定义数据（使用 utils::any 存储）
 *
 * 设计目标：
 * - 避免重复解析：每个处理器的解析结果可供后续处理器使用
 * - 解耦：处理器之间通过上下文传递数据，而非直接依赖
 * - 灵活性：可以动态添加自定义数据
 */
class PacketContext {
public:
    /**
     * 构造函数
     *
     * @param packet 数据包引用（生命周期必须覆盖整个处理过程）
     * @param stats_collector 统计收集器引用
     */
    explicit PacketContext(Packet& packet, StatisticsCollector& stats_collector)
        : packet_(packet)
        , stats_collector_(stats_collector)
        , should_drop_(false)
    {}

    // 禁止拷贝（避免意外拷贝大对象）
    PacketContext(const PacketContext&) = delete;
    PacketContext& operator=(const PacketContext&) = delete;

    // 允许移动
    PacketContext(PacketContext&&) = default;
    PacketContext& operator=(PacketContext&&) = default;

    // ========================================================================
    // 数据包访问
    // ========================================================================

    /**
     * 获取数据包（可修改，用于协议解析器填充 protocol_stack）
     */
    Packet& packet() { return packet_; }

    /**
     * 获取数据包（只读）
     */
    const Packet& packet() const { return packet_; }

    // ========================================================================
    // 流信息
    // ========================================================================

    /**
     * 设置关联的流
     */
    void set_flow(std::shared_ptr<flow::Flow> flow) {
        flow_ = flow;
    }

    /**
     * 获取关联的流
     */
    std::shared_ptr<flow::Flow> flow() const {
        return flow_;
    }

    /**
     * 是否有流信息
     */
    bool has_flow() const {
        return flow_ != nullptr;
    }

    // ========================================================================
    // L7 解析结果
    // ========================================================================

    /**
     * 设置 HTTP 请求解析结果
     */
    void set_http_request(std::shared_ptr<decoders::HttpRequest> request) {
        http_request_ = request;
    }

    /**
     * 获取 HTTP 请求
     */
    std::shared_ptr<decoders::HttpRequest> http_request() const {
        return http_request_;
    }

    /**
     * 是否有 HTTP 请求
     */
    bool has_http_request() const {
        return http_request_ != nullptr;
    }

    /**
     * 设置 HTTP 响应解析结果
     */
    void set_http_response(std::shared_ptr<decoders::HttpResponse> response) {
        http_response_ = response;
    }

    /**
     * 获取 HTTP 响应
     */
    std::shared_ptr<decoders::HttpResponse> http_response() const {
        return http_response_;
    }

    /**
     * 是否有 HTTP 响应
     */
    bool has_http_response() const {
        return http_response_ != nullptr;
    }

    /**
     * 设置 DNS 消息解析结果
     */
    void set_dns_message(std::shared_ptr<decoders::DnsMessage> message) {
        dns_message_ = message;
    }

    /**
     * 获取 DNS 消息
     */
    std::shared_ptr<decoders::DnsMessage> dns_message() const {
        return dns_message_;
    }

    /**
     * 是否有 DNS 消息
     */
    bool has_dns_message() const {
        return dns_message_ != nullptr;
    }

    // ========================================================================
    // 处理状态
    // ========================================================================

    /**
     * 标记应该丢弃数据包
     */
    void mark_as_drop() {
        should_drop_ = true;
    }

    /**
     * 是否应该丢弃数据包
     */
    bool should_drop() const {
        return should_drop_;
    }

    // ========================================================================
    // 统计收集器
    // ========================================================================

    /**
     * 获取统计收集器
     */
    StatisticsCollector& stats() {
        return stats_collector_;
    }

    // ========================================================================
    // 自定义数据（扩展点）
    // ========================================================================

    /**
     * 设置自定义数据
     *
     * @param key 键名
     * @param value 值（使用 utils::any 存储任意类型）
     */
    void set_custom_data(const std::string& key, utils::any value) {
        custom_data_[key] = std::move(value);
    }

    /**
     * 获取自定义数据
     *
     * @param key 键名
     * @return utils::any* 如果存在返回指针，否则返回 nullptr
     */
    utils::any* get_custom_data(const std::string& key) {
        auto it = custom_data_.find(key);
        if (it != custom_data_.end()) {
            return &it->second;
        }
        return nullptr;
    }

    /**
     * 检查是否存在自定义数据
     */
    bool has_custom_data(const std::string& key) const {
        return custom_data_.find(key) != custom_data_.end();
    }

private:
    // 数据包引用
    Packet& packet_;

    // 统计收集器引用
    StatisticsCollector& stats_collector_;

    // 流信息
    std::shared_ptr<flow::Flow> flow_;

    // L7 解析结果
    std::shared_ptr<decoders::HttpRequest> http_request_;
    std::shared_ptr<decoders::HttpResponse> http_response_;
    std::shared_ptr<decoders::DnsMessage> dns_message_;

    // 处理状态
    bool should_drop_;

    // 自定义数据（用于扩展）
    std::unordered_map<std::string, utils::any> custom_data_;
};

} // namespace core
} // namespace netguardian

#endif // NETGUARDIAN_CORE_PACKET_CONTEXT_H
