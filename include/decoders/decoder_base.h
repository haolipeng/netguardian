#ifndef NETGUARDIAN_DECODERS_DECODER_BASE_H
#define NETGUARDIAN_DECODERS_DECODER_BASE_H

#include "core/packet.h"
#include <memory>
#include <string>
#include <map>
#include <vector>
#include "utils/any.h"

namespace netguardian {
namespace decoders {

// 解码结果基类
class DecodedData {
public:
    virtual ~DecodedData() = default;
    virtual std::string to_string() const = 0;

    // 通用字段访问接口
    virtual bool has_field(const std::string& field_name) const = 0;
    virtual utils::any get_field(const std::string& field_name) const = 0;
};

// 解码器基类
class DecoderBase {
public:
    virtual ~DecoderBase() = default;

    // 解码数据包，返回解码后的数据结构
    virtual std::shared_ptr<DecodedData> decode(const core::Packet& packet) = 0;

    // 获取解码器名称
    virtual std::string name() const = 0;

    // 检查是否可以解码此数据包
    virtual bool can_decode(const core::Packet& packet) const = 0;
};

using DecoderPtr = std::shared_ptr<DecoderBase>;

// 解码结果容器 - 存储一个数据包的所有层次解码结果
class DecodedPacket {
public:
    DecodedPacket() = default;

    // 添加某一层的解码结果
    void add_layer(const std::string& protocol, std::shared_ptr<DecodedData> data) {
        layers_[protocol] = data;
    }

    // 获取某一层的解码结果
    std::shared_ptr<DecodedData> get_layer(const std::string& protocol) const {
        auto it = layers_.find(protocol);
        return (it != layers_.end()) ? it->second : nullptr;
    }

    // 检查是否包含某层协议
    bool has_layer(const std::string& protocol) const {
        return layers_.find(protocol) != layers_.end();
    }

    // 获取所有层的协议名称
    std::vector<std::string> get_protocols() const {
        std::vector<std::string> protocols;
        for (const auto& pair : layers_) {
            protocols.push_back(pair.first);
        }
        return protocols;
    }

private:
    std::map<std::string, std::shared_ptr<DecodedData>> layers_;
};

} // namespace decoders
} // namespace netguardian

#endif // NETGUARDIAN_DECODERS_DECODER_BASE_H
