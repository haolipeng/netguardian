#ifndef NETGUARDIAN_CORE_PACKET_PROCESSOR_H
#define NETGUARDIAN_CORE_PACKET_PROCESSOR_H

#include <memory>

namespace netguardian {
namespace core {

// 前向声明
class PacketContext;

/**
 * ProcessResult - 处理结果
 *
 * 指示处理器执行后的动作
 */
enum class ProcessResult {
    CONTINUE,   // 继续下一个处理器
    STOP,       // 停止处理管道（正常停止）
    DROP        // 丢弃数据包（异常或规则匹配）
};

/**
 * PacketProcessor - 数据包处理器接口
 *
 * 这是所有数据包处理器的基类接口。
 * 每个处理器负责一个特定的功能（协议解析、流跟踪、规则检测等）。
 *
 * 设计原则：
 * - 单一职责：每个处理器只做一件事
 * - 无状态或最小状态：尽量避免在处理器内部保持状态
 * - 链式处理：通过 PacketContext 传递数据
 */
class PacketProcessor {
public:
    virtual ~PacketProcessor() = default;

    /**
     * 处理数据包
     *
     * @param ctx 数据包上下文（包含数据包和处理过程中的状态）
     * @return ProcessResult 处理结果
     */
    virtual ProcessResult process(PacketContext& ctx) = 0;

    /**
     * 获取处理器名称（用于日志和调试）
     */
    virtual const char* name() const = 0;

    /**
     * 初始化处理器
     *
     * @return true 成功，false 失败
     */
    virtual bool initialize() { return true; }

    /**
     * 停止处理器（清理资源、导出数据等）
     */
    virtual void shutdown() {}

    /**
     * 刷新缓冲区（导出流、刷新统计等）
     */
    virtual void flush() {}
};

using PacketProcessorPtr = std::unique_ptr<PacketProcessor>;

} // namespace core
} // namespace netguardian

#endif // NETGUARDIAN_CORE_PACKET_PROCESSOR_H
