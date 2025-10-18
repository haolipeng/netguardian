#include "decoders/dns_parser.h"
#include <sstream>
#include <arpa/inet.h>
#include <cstring>
#include <iomanip>
#include <algorithm>
#include <cmath>

namespace netguardian {
namespace decoders {

// ============================================================================
// DnsFlags 实现
// ============================================================================

std::string DnsFlags::to_string() const {
    std::ostringstream oss;
    oss << "[" << (qr ? "Response" : "Query") << "] ";
    oss << "Opcode=" << static_cast<int>(opcode) << " ";
    if (aa) oss << "AA ";
    if (tc) oss << "TC ";
    if (rd) oss << "RD ";
    if (ra) oss << "RA ";
    if (ad) oss << "AD ";
    if (cd) oss << "CD ";
    oss << "RCODE=" << static_cast<int>(rcode);
    return oss.str();
}

// ============================================================================
// RDATA 结构实现
// ============================================================================

std::string MXRdata::to_string() const {
    std::ostringstream oss;
    oss << preference << " " << exchange;
    return oss.str();
}

std::string TXTRdata::to_string() const {
    std::ostringstream oss;
    bool first = true;
    for (const auto& text : texts) {
        if (!first) oss << "; ";
        oss << "\"" << text << "\"";
        first = false;
    }
    return oss.str();
}

std::string SOARdata::to_string() const {
    std::ostringstream oss;
    oss << mname << " " << rname << " "
        << serial << " " << refresh << " "
        << retry << " " << expire << " " << minimum;
    return oss.str();
}

std::string SRVRdata::to_string() const {
    std::ostringstream oss;
    oss << priority << " " << weight << " " << port << " " << target;
    return oss.str();
}

std::string RawRdata::to_string() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < std::min(data.size(), size_t(32)); i++) {
        oss << std::setw(2) << static_cast<int>(data[i]);
        if (i < data.size() - 1) oss << " ";
    }
    if (data.size() > 32) {
        oss << " ... (" << std::dec << data.size() << " bytes)";
    }
    return oss.str();
}

// ============================================================================
// DnsQuestion 实现
// ============================================================================

std::string DnsQuestion::to_string() const {
    std::ostringstream oss;
    oss << qname << " "
        << DnsParser::class_to_string(qclass) << " "
        << DnsParser::record_type_to_string(qtype);
    return oss.str();
}

// ============================================================================
// DnsResourceRecord 实现
// ============================================================================

std::string DnsResourceRecord::to_string() const {
    std::ostringstream oss;
    oss << name << " "
        << ttl << " "
        << DnsParser::class_to_string(rclass) << " "
        << DnsParser::record_type_to_string(type) << " "
        << rdata_to_string();
    return oss.str();
}

std::string DnsResourceRecord::rdata_to_string() const {
    if (!rdata_parsed) {
        return RawRdata{rdata_raw}.to_string();
    }

    if (a_rdata) return a_rdata->to_string();
    if (aaaa_rdata) return aaaa_rdata->to_string();
    if (domain_rdata) return domain_rdata->to_string();
    if (mx_rdata) return mx_rdata->to_string();
    if (txt_rdata) return txt_rdata->to_string();
    if (soa_rdata) return soa_rdata->to_string();
    if (srv_rdata) return srv_rdata->to_string();
    if (raw_rdata) return raw_rdata->to_string();

    return "";
}

std::string DnsResourceRecord::get_ip_address() const {
    if (a_rdata) return a_rdata->address;
    if (aaaa_rdata) return aaaa_rdata->address;
    return "";
}

std::string DnsResourceRecord::get_domain() const {
    if (domain_rdata) return domain_rdata->domain;
    return "";
}

// ============================================================================
// DnsMessage 实现
// ============================================================================

std::vector<std::string> DnsMessage::get_queried_domains() const {
    std::vector<std::string> domains;
    for (const auto& q : questions) {
        domains.push_back(q.qname);
    }
    return domains;
}

std::vector<std::string> DnsMessage::get_resolved_ips() const {
    std::vector<std::string> ips;
    for (const auto& ans : answers) {
        std::string ip = ans.get_ip_address();
        if (!ip.empty()) {
            ips.push_back(ip);
        }
    }
    return ips;
}

std::vector<std::string> DnsMessage::get_all_domains() const {
    std::vector<std::string> domains;

    // 查询域名
    for (const auto& q : questions) {
        domains.push_back(q.qname);
    }

    // 答复中的域名
    for (const auto& ans : answers) {
        if (ans.domain_rdata) {
            domains.push_back(ans.domain_rdata->domain);
        }
    }

    // 授权记录中的域名
    for (const auto& ns : authorities) {
        if (ns.domain_rdata) {
            domains.push_back(ns.domain_rdata->domain);
        }
    }

    return domains;
}

std::string DnsMessage::to_string() const {
    std::ostringstream oss;
    oss << "DNS [ID: " << id << "] ";
    oss << (is_query() ? "Query" : "Response") << "\n";
    oss << "  Flags: " << flags.to_string() << "\n";
    oss << "  Questions: " << qd_count
        << ", Answers: " << an_count
        << ", Authority: " << ns_count
        << ", Additional: " << ar_count << "\n";

    if (!questions.empty()) {
        oss << "  Queries:\n";
        for (const auto& q : questions) {
            oss << "    " << q.to_string() << "\n";
        }
    }

    if (!answers.empty()) {
        oss << "  Answers:\n";
        for (const auto& ans : answers) {
            oss << "    " << ans.to_string() << "\n";
        }
    }

    return oss.str();
}

// ============================================================================
// DnsParser 公共方法
// ============================================================================

int DnsParser::parse_message(const uint8_t* data, size_t len, DnsMessage& message) {
    if (!data || len < 12) {
        return -1;  // DNS 头部至少 12 字节
    }

    // 解析头部
    if (!parse_header(data, len, message)) {
        return -1;
    }

    size_t offset = 12;  // 跳过头部

    // 解析问题部分
    for (uint16_t i = 0; i < message.qd_count && offset < len; i++) {
        DnsQuestion question;
        if (!parse_question(data, len, offset, question)) {
            break;
        }
        message.questions.push_back(question);
    }

    // 解析答复部分
    for (uint16_t i = 0; i < message.an_count && offset < len; i++) {
        DnsResourceRecord rr;
        if (!parse_resource_record(data, len, offset, rr)) {
            break;
        }
        message.answers.push_back(rr);
    }

    // 解析授权部分
    for (uint16_t i = 0; i < message.ns_count && offset < len; i++) {
        DnsResourceRecord rr;
        if (!parse_resource_record(data, len, offset, rr)) {
            break;
        }
        message.authorities.push_back(rr);
    }

    // 解析附加部分
    for (uint16_t i = 0; i < message.ar_count && offset < len; i++) {
        DnsResourceRecord rr;
        if (!parse_resource_record(data, len, offset, rr)) {
            break;
        }
        message.additionals.push_back(rr);
    }

    return offset;
}

std::string DnsParser::record_type_to_string(DnsRecordType type) {
    switch (type) {
        case DnsRecordType::A: return "A";
        case DnsRecordType::NS: return "NS";
        case DnsRecordType::CNAME: return "CNAME";
        case DnsRecordType::SOA: return "SOA";
        case DnsRecordType::PTR: return "PTR";
        case DnsRecordType::MX: return "MX";
        case DnsRecordType::TXT: return "TXT";
        case DnsRecordType::AAAA: return "AAAA";
        case DnsRecordType::SRV: return "SRV";
        case DnsRecordType::NAPTR: return "NAPTR";
        case DnsRecordType::OPT: return "OPT";
        case DnsRecordType::DS: return "DS";
        case DnsRecordType::RRSIG: return "RRSIG";
        case DnsRecordType::NSEC: return "NSEC";
        case DnsRecordType::DNSKEY: return "DNSKEY";
        case DnsRecordType::TLSA: return "TLSA";
        case DnsRecordType::CAA: return "CAA";
        case DnsRecordType::ANY: return "ANY";
        default: return "TYPE" + std::to_string(static_cast<uint16_t>(type));
    }
}

std::string DnsParser::class_to_string(DnsClass cls) {
    switch (cls) {
        case DnsClass::IN: return "IN";
        case DnsClass::CS: return "CS";
        case DnsClass::CH: return "CH";
        case DnsClass::HS: return "HS";
        case DnsClass::ANY: return "ANY";
        default: return "CLASS" + std::to_string(static_cast<uint16_t>(cls));
    }
}

std::string DnsParser::opcode_to_string(DnsOpcode opcode) {
    switch (opcode) {
        case DnsOpcode::QUERY: return "QUERY";
        case DnsOpcode::IQUERY: return "IQUERY";
        case DnsOpcode::STATUS: return "STATUS";
        case DnsOpcode::NOTIFY: return "NOTIFY";
        case DnsOpcode::UPDATE: return "UPDATE";
        default: return "OPCODE" + std::to_string(static_cast<uint8_t>(opcode));
    }
}

std::string DnsParser::rcode_to_string(DnsResponseCode rcode) {
    switch (rcode) {
        case DnsResponseCode::NOERROR: return "NOERROR";
        case DnsResponseCode::FORMERR: return "FORMERR";
        case DnsResponseCode::SERVFAIL: return "SERVFAIL";
        case DnsResponseCode::NXDOMAIN: return "NXDOMAIN";
        case DnsResponseCode::NOTIMP: return "NOTIMP";
        case DnsResponseCode::REFUSED: return "REFUSED";
        case DnsResponseCode::YXDOMAIN: return "YXDOMAIN";
        case DnsResponseCode::YXRRSET: return "YXRRSET";
        case DnsResponseCode::NXRRSET: return "NXRRSET";
        case DnsResponseCode::NOTAUTH: return "NOTAUTH";
        case DnsResponseCode::NOTZONE: return "NOTZONE";
        default: return "RCODE" + std::to_string(static_cast<uint8_t>(rcode));
    }
}

// ============================================================================
// DnsParser 私有方法
// ============================================================================

std::string DnsParser::parse_domain_name(const uint8_t* msg_start, size_t msg_len,
                                        size_t& offset) {
    std::string domain;
    bool jumped = false;
    size_t orig_offset = offset;
    size_t max_jumps = 10;  // 防止无限循环

    while (offset < msg_len && max_jumps > 0) {
        uint8_t label_len = msg_start[offset];

        // 检查是否是指针（压缩）
        if ((label_len & 0xC0) == 0xC0) {
            if (offset + 1 >= msg_len) break;

            // 指针：12位偏移量
            uint16_t pointer = ((label_len & 0x3F) << 8) | msg_start[offset + 1];
            if (!jumped) {
                orig_offset = offset + 2;
                jumped = true;
            }
            offset = pointer;
            max_jumps--;
            continue;
        }

        // 标签结束
        if (label_len == 0) {
            offset++;
            break;
        }

        // 检查标签长度
        if (label_len > 63 || offset + 1 + label_len > msg_len) {
            break;
        }

        // 添加标签
        if (!domain.empty()) {
            domain += ".";
        }
        domain.append(reinterpret_cast<const char*>(msg_start + offset + 1), label_len);
        offset += 1 + label_len;
    }

    // 如果跳转过，使用原始偏移量的后续位置
    if (jumped) {
        offset = orig_offset;
    }

    return domain;
}

bool DnsParser::parse_header(const uint8_t* data, size_t len, DnsMessage& message) {
    if (len < 12) return false;

    message.id = ntohs(*reinterpret_cast<const uint16_t*>(data));

    uint16_t flags_raw = ntohs(*reinterpret_cast<const uint16_t*>(data + 2));
    message.flags.qr = (flags_raw & 0x8000) != 0;
    message.flags.opcode = static_cast<DnsOpcode>((flags_raw >> 11) & 0x0F);
    message.flags.aa = (flags_raw & 0x0400) != 0;
    message.flags.tc = (flags_raw & 0x0200) != 0;
    message.flags.rd = (flags_raw & 0x0100) != 0;
    message.flags.ra = (flags_raw & 0x0080) != 0;
    message.flags.z = (flags_raw & 0x0040) != 0;
    message.flags.ad = (flags_raw & 0x0020) != 0;
    message.flags.cd = (flags_raw & 0x0010) != 0;
    message.flags.rcode = static_cast<DnsResponseCode>(flags_raw & 0x000F);

    message.qd_count = ntohs(*reinterpret_cast<const uint16_t*>(data + 4));
    message.an_count = ntohs(*reinterpret_cast<const uint16_t*>(data + 6));
    message.ns_count = ntohs(*reinterpret_cast<const uint16_t*>(data + 8));
    message.ar_count = ntohs(*reinterpret_cast<const uint16_t*>(data + 10));

    return true;
}

bool DnsParser::parse_question(const uint8_t* msg_start, size_t msg_len,
                               size_t& offset, DnsQuestion& question) {
    // 解析查询名称
    question.qname = parse_domain_name(msg_start, msg_len, offset);

    if (offset + 4 > msg_len) {
        return false;
    }

    // 查询类型和类
    question.qtype = static_cast<DnsRecordType>(
        ntohs(*reinterpret_cast<const uint16_t*>(msg_start + offset)));
    offset += 2;

    question.qclass = static_cast<DnsClass>(
        ntohs(*reinterpret_cast<const uint16_t*>(msg_start + offset)));
    offset += 2;

    return true;
}

bool DnsParser::parse_resource_record(const uint8_t* msg_start, size_t msg_len,
                                     size_t& offset, DnsResourceRecord& rr) {
    // 解析名称
    rr.name = parse_domain_name(msg_start, msg_len, offset);

    if (offset + 10 > msg_len) {
        return false;
    }

    // 类型、类、TTL、数据长度
    rr.type = static_cast<DnsRecordType>(
        ntohs(*reinterpret_cast<const uint16_t*>(msg_start + offset)));
    offset += 2;

    rr.rclass = static_cast<DnsClass>(
        ntohs(*reinterpret_cast<const uint16_t*>(msg_start + offset)));
    offset += 2;

    rr.ttl = ntohl(*reinterpret_cast<const uint32_t*>(msg_start + offset));
    offset += 4;

    rr.rdlength = ntohs(*reinterpret_cast<const uint16_t*>(msg_start + offset));
    offset += 2;

    // 检查长度
    if (offset + rr.rdlength > msg_len) {
        return false;
    }

    // 保存原始 RDATA
    rr.rdata_raw.resize(rr.rdlength);
    std::memcpy(rr.rdata_raw.data(), msg_start + offset, rr.rdlength);

    // 解析 RDATA
    parse_rdata(msg_start, msg_len, rr, offset);

    offset += rr.rdlength;

    return true;
}

void DnsParser::parse_rdata(const uint8_t* msg_start, size_t msg_len,
                           DnsResourceRecord& rr, size_t rdata_offset) {
    const uint8_t* rdata = msg_start + rdata_offset;
    uint16_t rdlength = rr.rdlength;

    switch (rr.type) {
        case DnsRecordType::A:
            rr.a_rdata = parse_a_rdata(rdata, rdlength);
            rr.rdata_parsed = (rr.a_rdata != nullptr);
            break;

        case DnsRecordType::AAAA:
            rr.aaaa_rdata = parse_aaaa_rdata(rdata, rdlength);
            rr.rdata_parsed = (rr.aaaa_rdata != nullptr);
            break;

        case DnsRecordType::CNAME:
        case DnsRecordType::NS:
        case DnsRecordType::PTR:
            rr.domain_rdata = parse_domain_rdata(msg_start, msg_len, rdata_offset, rdlength);
            rr.rdata_parsed = (rr.domain_rdata != nullptr);
            break;

        case DnsRecordType::MX:
            rr.mx_rdata = parse_mx_rdata(msg_start, msg_len, rdata_offset, rdlength);
            rr.rdata_parsed = (rr.mx_rdata != nullptr);
            break;

        case DnsRecordType::TXT:
            rr.txt_rdata = parse_txt_rdata(rdata, rdlength);
            rr.rdata_parsed = (rr.txt_rdata != nullptr);
            break;

        case DnsRecordType::SOA:
            rr.soa_rdata = parse_soa_rdata(msg_start, msg_len, rdata_offset, rdlength);
            rr.rdata_parsed = (rr.soa_rdata != nullptr);
            break;

        case DnsRecordType::SRV:
            rr.srv_rdata = parse_srv_rdata(msg_start, msg_len, rdata_offset, rdlength);
            rr.rdata_parsed = (rr.srv_rdata != nullptr);
            break;

        default:
            // 未知类型，保存原始数据
            rr.raw_rdata = std::make_shared<RawRdata>();
            rr.raw_rdata->data = rr.rdata_raw;
            rr.rdata_parsed = true;
            break;
    }
}

// ============================================================================
// 具体 RDATA 解析器
// ============================================================================

std::shared_ptr<ARdata> DnsParser::parse_a_rdata(const uint8_t* rdata, uint16_t rdlength) {
    if (rdlength != 4) return nullptr;

    auto result = std::make_shared<ARdata>();
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, rdata, buf, sizeof(buf));
    result->address = buf;

    return result;
}

std::shared_ptr<AAAARdata> DnsParser::parse_aaaa_rdata(const uint8_t* rdata, uint16_t rdlength) {
    if (rdlength != 16) return nullptr;

    auto result = std::make_shared<AAAARdata>();
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, rdata, buf, sizeof(buf));
    result->address = buf;

    return result;
}

std::shared_ptr<DomainRdata> DnsParser::parse_domain_rdata(
    const uint8_t* msg_start, size_t msg_len, size_t rdata_offset, uint16_t rdlength) {

    size_t offset = rdata_offset;
    std::string domain = parse_domain_name(msg_start, msg_len, offset);

    if (domain.empty()) return nullptr;

    auto result = std::make_shared<DomainRdata>();
    result->domain = domain;
    return result;
}

std::shared_ptr<MXRdata> DnsParser::parse_mx_rdata(
    const uint8_t* msg_start, size_t msg_len, size_t rdata_offset, uint16_t rdlength) {

    if (rdlength < 3) return nullptr;

    auto result = std::make_shared<MXRdata>();

    // 解析优先级（2 字节）
    result->preference = ntohs(*reinterpret_cast<const uint16_t*>(msg_start + rdata_offset));

    // 解析交换域名
    size_t offset = rdata_offset + 2;
    result->exchange = parse_domain_name(msg_start, msg_len, offset);

    return result;
}

std::shared_ptr<TXTRdata> DnsParser::parse_txt_rdata(const uint8_t* rdata, uint16_t rdlength) {
    auto result = std::make_shared<TXTRdata>();

    size_t offset = 0;
    while (offset < rdlength) {
        uint8_t len = rdata[offset++];
        if (offset + len > rdlength) break;

        std::string text(reinterpret_cast<const char*>(rdata + offset), len);
        result->texts.push_back(text);
        offset += len;
    }

    return result;
}

std::shared_ptr<SOARdata> DnsParser::parse_soa_rdata(
    const uint8_t* msg_start, size_t msg_len, size_t rdata_offset, uint16_t rdlength) {

    auto result = std::make_shared<SOARdata>();

    // 解析 MNAME
    size_t offset = rdata_offset;
    result->mname = parse_domain_name(msg_start, msg_len, offset);

    // 解析 RNAME
    result->rname = parse_domain_name(msg_start, msg_len, offset);

    // 检查剩余空间（需要 20 字节：5 个 uint32_t）
    if (offset + 20 > rdata_offset + rdlength) {
        return nullptr;
    }

    // 解析序列号和时间参数
    result->serial = ntohl(*reinterpret_cast<const uint32_t*>(msg_start + offset));
    offset += 4;
    result->refresh = ntohl(*reinterpret_cast<const uint32_t*>(msg_start + offset));
    offset += 4;
    result->retry = ntohl(*reinterpret_cast<const uint32_t*>(msg_start + offset));
    offset += 4;
    result->expire = ntohl(*reinterpret_cast<const uint32_t*>(msg_start + offset));
    offset += 4;
    result->minimum = ntohl(*reinterpret_cast<const uint32_t*>(msg_start + offset));

    return result;
}

std::shared_ptr<SRVRdata> DnsParser::parse_srv_rdata(
    const uint8_t* msg_start, size_t msg_len, size_t rdata_offset, uint16_t rdlength) {

    if (rdlength < 7) return nullptr;  // 至少 6 字节 + 1 字节域名

    auto result = std::make_shared<SRVRdata>();

    // 解析 Priority, Weight, Port（各 2 字节）
    result->priority = ntohs(*reinterpret_cast<const uint16_t*>(msg_start + rdata_offset));
    result->weight = ntohs(*reinterpret_cast<const uint16_t*>(msg_start + rdata_offset + 2));
    result->port = ntohs(*reinterpret_cast<const uint16_t*>(msg_start + rdata_offset + 4));

    // 解析目标域名
    size_t offset = rdata_offset + 6;
    result->target = parse_domain_name(msg_start, msg_len, offset);

    return result;
}

} // namespace decoders
} // namespace netguardian
