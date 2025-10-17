#ifndef NETGUARDIAN_DECODERS_TCP_DECODER_H
#define NETGUARDIAN_DECODERS_TCP_DECODER_H

#include "decoders/decoder_base.h"
#include <sstream>
#include <iomanip>
#include <vector>

namespace netguardian {
namespace decoders {

// TCP 标志位
struct TcpFlags {
    bool fin;
    bool syn;
    bool rst;
    bool psh;
    bool ack;
    bool urg;
    bool ece;
    bool cwr;

    TcpFlags() : fin(false), syn(false), rst(false), psh(false),
                 ack(false), urg(false), ece(false), cwr(false) {}

    std::string to_string() const {
        std::string result;
        if (syn) result += "SYN ";
        if (ack) result += "ACK ";
        if (fin) result += "FIN ";
        if (rst) result += "RST ";
        if (psh) result += "PSH ";
        if (urg) result += "URG ";
        if (ece) result += "ECE ";
        if (cwr) result += "CWR ";
        if (!result.empty()) result.pop_back(); // 移除最后的空格
        return result;
    }
};

// TCP 解码数据
class TcpData : public DecodedData {
public:
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;  // 头部长度（32位字为单位）
    TcpFlags flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;

    // 选项
    bool has_options;
    std::vector<uint8_t> options;

    TcpData()
        : src_port(0), dst_port(0), seq_num(0), ack_num(0)
        , data_offset(0), window_size(0), checksum(0)
        , urgent_pointer(0), has_options(false)
    {}

    std::string to_string() const override {
        std::ostringstream oss;
        oss << "TCP [";
        oss << src_port << " -> " << dst_port;
        oss << ", Seq: " << seq_num;
        if (flags.ack) {
            oss << ", Ack: " << ack_num;
        }
        oss << ", Win: " << window_size;
        std::string flags_str = flags.to_string();
        if (!flags_str.empty()) {
            oss << ", Flags: " << flags_str;
        }
        oss << "]";
        return oss.str();
    }

    bool has_field(const std::string& field_name) const override {
        return field_name == "src_port" || field_name == "dst_port" ||
               field_name == "seq_num" || field_name == "ack_num" ||
               field_name == "window_size";
    }

    std::any get_field(const std::string& field_name) const override {
        if (field_name == "src_port") return src_port;
        if (field_name == "dst_port") return dst_port;
        if (field_name == "seq_num") return seq_num;
        if (field_name == "ack_num") return ack_num;
        if (field_name == "window_size") return window_size;
        return std::any();
    }

    uint16_t header_length() const {
        return data_offset * 4;
    }
};

// TCP 解码器
class TcpDecoder : public DecoderBase {
public:
    std::shared_ptr<DecodedData> decode(const core::Packet& packet) override;
    std::string name() const override { return "TCP"; }
    bool can_decode(const core::Packet& packet) const override;
};

} // namespace decoders
} // namespace netguardian

#endif // NETGUARDIAN_DECODERS_TCP_DECODER_H
