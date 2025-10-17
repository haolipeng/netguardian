#ifndef NETGUARDIAN_DECODERS_DNS_DECODER_H
#define NETGUARDIAN_DECODERS_DNS_DECODER_H

#include "decoders/decoder_base.h"
#include <vector>
#include <sstream>

namespace netguardian {
namespace decoders {

// DNS 查询类型
enum class DnsQType {
    A = 1,      // IPv4 地址
    NS = 2,     // 名称服务器
    CNAME = 5,  // 规范名称
    SOA = 6,    // 授权开始
    PTR = 12,   // 指针记录
    MX = 15,    // 邮件交换
    TXT = 16,   // 文本记录
    AAAA = 28,  // IPv6 地址
    SRV = 33,   // 服务记录
    ANY = 255   // 所有记录
};

// DNS 查询
struct DnsQuery {
    std::string qname;
    uint16_t qtype;
    uint16_t qclass;

    std::string to_string() const {
        std::ostringstream oss;
        oss << qname << " (type=" << qtype << ", class=" << qclass << ")";
        return oss.str();
    }
};

// DNS 资源记录
struct DnsResourceRecord {
    std::string name;
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    std::vector<uint8_t> rdata;

    std::string to_string() const {
        std::ostringstream oss;
        oss << name << " (type=" << type << ", ttl=" << ttl << ")";
        return oss.str();
    }
};

// DNS 解码数据
class DnsData : public DecodedData {
public:
    // DNS 头部
    uint16_t transaction_id;
    bool is_query;
    uint8_t opcode;
    bool authoritative;
    bool truncated;
    bool recursion_desired;
    bool recursion_available;
    uint8_t response_code;

    // 计数
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;

    // 查询和答复
    std::vector<DnsQuery> queries;
    std::vector<DnsResourceRecord> answers;

    DnsData()
        : transaction_id(0), is_query(true), opcode(0)
        , authoritative(false), truncated(false)
        , recursion_desired(false), recursion_available(false)
        , response_code(0)
        , question_count(0), answer_count(0)
        , authority_count(0), additional_count(0)
    {}

    std::string to_string() const override {
        std::ostringstream oss;
        oss << "DNS [";
        oss << (is_query ? "Query" : "Response");
        oss << ", ID: " << transaction_id;
        if (!queries.empty()) {
            oss << ", Q: " << queries[0].qname;
        }
        if (!is_query) {
            oss << ", Answers: " << answer_count;
        }
        oss << "]";
        return oss.str();
    }

    bool has_field(const std::string& field_name) const override {
        return field_name == "transaction_id" || field_name == "is_query" ||
               field_name == "question_count" || field_name == "answer_count";
    }

    std::any get_field(const std::string& field_name) const override {
        if (field_name == "transaction_id") return transaction_id;
        if (field_name == "is_query") return is_query;
        if (field_name == "question_count") return question_count;
        if (field_name == "answer_count") return answer_count;
        return std::any();
    }
};

// DNS 解码器
class DnsDecoder : public DecoderBase {
public:
    std::shared_ptr<DecodedData> decode(const core::Packet& packet) override;
    std::string name() const override { return "DNS"; }
    bool can_decode(const core::Packet& packet) const override;

private:
    std::string parse_domain_name(const uint8_t* data, size_t len,
                                  size_t& offset, const uint8_t* msg_start);
};

} // namespace decoders
} // namespace netguardian

#endif // NETGUARDIAN_DECODERS_DNS_DECODER_H
