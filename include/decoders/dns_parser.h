#ifndef NETGUARDIAN_DECODERS_DNS_PARSER_H
#define NETGUARDIAN_DECODERS_DNS_PARSER_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <map>

namespace netguardian {
namespace decoders {

// ============================================================================
// DNS 记录类型
// ============================================================================

enum class DnsRecordType : uint16_t {
    A = 1,          // IPv4 地址
    NS = 2,         // 名称服务器
    MD = 3,         // 邮件目的地（已废弃）
    MF = 4,         // 邮件转发器（已废弃）
    CNAME = 5,      // 规范名称
    SOA = 6,        // 授权开始
    MB = 7,         // 邮箱域名
    MG = 8,         // 邮件组成员
    MR = 9,         // 邮件重命名域名
    NULL_RECORD = 10,  // 空记录
    WKS = 11,       // 众所周知的服务
    PTR = 12,       // 指针记录
    HINFO = 13,     // 主机信息
    MINFO = 14,     // 邮箱信息
    MX = 15,        // 邮件交换
    TXT = 16,       // 文本记录
    RP = 17,        // 负责人
    AFSDB = 18,     // AFS 数据库位置
    X25 = 19,       // X.25 地址
    ISDN = 20,      // ISDN 地址
    RT = 21,        // 路由选择
    NSAP = 22,      // NSAP 地址
    NSAP_PTR = 23,  // NSAP 指针
    SIG = 24,       // 签名
    KEY = 25,       // 密钥
    PX = 26,        // 指针到 X.400
    GPOS = 27,      // 地理位置
    AAAA = 28,      // IPv6 地址
    LOC = 29,       // 位置信息
    NXT = 30,       // 下一个（已废弃）
    EID = 31,       // 端点标识符
    NIMLOC = 32,    // Nimrod 定位器
    SRV = 33,       // 服务记录
    ATMA = 34,      // ATM 地址
    NAPTR = 35,     // 命名权限指针
    KX = 36,        // 密钥交换器
    CERT = 37,      // 证书
    A6 = 38,        // IPv6 地址（已废弃）
    DNAME = 39,     // 委托名称
    SINK = 40,      // SINK
    OPT = 41,       // OPT 伪记录
    APL = 42,       // APL
    DS = 43,        // 委托签名者
    SSHFP = 44,     // SSH 公钥指纹
    IPSECKEY = 45,  // IPSEC 密钥
    RRSIG = 46,     // DNSSEC 签名
    NSEC = 47,      // 下一个安全
    DNSKEY = 48,    // DNS 密钥
    DHCID = 49,     // DHCP 标识符
    NSEC3 = 50,     // NSEC3
    NSEC3PARAM = 51, // NSEC3 参数
    TLSA = 52,      // TLSA
    SMIMEA = 53,    // S/MIME 证书关联
    HIP = 55,       // 主机身份协议
    NINFO = 56,     // NINFO
    RKEY = 57,      // RKEY
    TALINK = 58,    // 信任锚链接
    CDS = 59,       // 子 DS
    CDNSKEY = 60,   // 子 DNSKEY
    OPENPGPKEY = 61, // OpenPGP 密钥
    CSYNC = 62,     // 子同步
    SPF = 99,       // SPF（已废弃，使用 TXT）
    UINFO = 100,    // UINFO
    UID = 101,      // UID
    GID = 102,      // GID
    UNSPEC = 103,   // UNSPEC
    NID = 104,      // NID
    L32 = 105,      // L32
    L64 = 106,      // L64
    LP = 107,       // LP
    EUI48 = 108,    // EUI-48 地址
    EUI64 = 109,    // EUI-64 地址
    TKEY = 249,     // 交易密钥
    TSIG = 250,     // 交易签名
    IXFR = 251,     // 增量传输
    AXFR = 252,     // 传输整个区域
    MAILB = 253,    // 邮箱相关记录
    MAILA = 254,    // 邮件代理
    ANY = 255,      // 所有记录
    URI = 256,      // URI
    CAA = 257,      // 证书颁发机构授权
    TA = 32768,     // DNSSEC 信任锚
    DLV = 32769     // DNSSEC 前瞻验证
};

// DNS 类
enum class DnsClass : uint16_t {
    IN = 1,         // Internet
    CS = 2,         // CSNET（已废弃）
    CH = 3,         // CHAOS
    HS = 4,         // Hesiod
    NONE = 254,     // NONE
    ANY = 255       // ANY
};

// DNS 操作码
enum class DnsOpcode : uint8_t {
    QUERY = 0,      // 标准查询
    IQUERY = 1,     // 反向查询（已废弃）
    STATUS = 2,     // 服务器状态请求
    NOTIFY = 4,     // 通知
    UPDATE = 5      // 动态更新
};

// DNS 响应代码
enum class DnsResponseCode : uint8_t {
    NOERROR = 0,    // 无错误
    FORMERR = 1,    // 格式错误
    SERVFAIL = 2,   // 服务器失败
    NXDOMAIN = 3,   // 名称不存在
    NOTIMP = 4,     // 未实现
    REFUSED = 5,    // 拒绝
    YXDOMAIN = 6,   // 不应该存在的名称
    YXRRSET = 7,    // 不应该存在的 RR 集
    NXRRSET = 8,    // 应该存在的 RR 集不存在
    NOTAUTH = 9,    // 服务器不是授权的
    NOTZONE = 10,   // 名称不在区域内
    BADVERS = 16,   // 错误的 OPT 版本
    BADSIG = 16,    // TSIG 签名失败
    BADKEY = 17,    // 密钥未被识别
    BADTIME = 18,   // 签名超出时间窗口
    BADMODE = 19,   // 错误的 TKEY 模式
    BADNAME = 20,   // 重复的密钥名称
    BADALG = 21     // 算法不受支持
};

// ============================================================================
// DNS 标志位
// ============================================================================

struct DnsFlags {
    bool qr;                    // Query/Response flag
    DnsOpcode opcode;           // Opcode
    bool aa;                    // Authoritative Answer
    bool tc;                    // Truncated
    bool rd;                    // Recursion Desired
    bool ra;                    // Recursion Available
    bool z;                     // Reserved (must be zero)
    bool ad;                    // Authenticated Data
    bool cd;                    // Checking Disabled
    DnsResponseCode rcode;      // Response Code

    DnsFlags()
        : qr(false), opcode(DnsOpcode::QUERY), aa(false), tc(false)
        , rd(false), ra(false), z(false), ad(false), cd(false)
        , rcode(DnsResponseCode::NOERROR)
    {}

    std::string to_string() const;
};

// ============================================================================
// DNS RDATA 结构
// ============================================================================

// A 记录数据
struct ARdata {
    std::string address;  // IPv4 地址字符串

    std::string to_string() const { return address; }
};

// AAAA 记录数据
struct AAAARdata {
    std::string address;  // IPv6 地址字符串

    std::string to_string() const { return address; }
};

// CNAME/NS/PTR 记录数据
struct DomainRdata {
    std::string domain;

    std::string to_string() const { return domain; }
};

// MX 记录数据
struct MXRdata {
    uint16_t preference;
    std::string exchange;

    std::string to_string() const;
};

// TXT 记录数据
struct TXTRdata {
    std::vector<std::string> texts;

    std::string to_string() const;
};

// SOA 记录数据
struct SOARdata {
    std::string mname;      // 主名称服务器
    std::string rname;      // 负责人邮箱
    uint32_t serial;        // 序列号
    uint32_t refresh;       // 刷新时间
    uint32_t retry;         // 重试时间
    uint32_t expire;        // 过期时间
    uint32_t minimum;       // 最小 TTL

    std::string to_string() const;
};

// SRV 记录数据
struct SRVRdata {
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    std::string target;

    std::string to_string() const;
};

// 通用 RDATA（未解析类型）
struct RawRdata {
    std::vector<uint8_t> data;

    std::string to_string() const;
};

// ============================================================================
// DNS 问题部分
// ============================================================================

struct DnsQuestion {
    std::string qname;
    DnsRecordType qtype;
    DnsClass qclass;

    std::string to_string() const;
};

// ============================================================================
// DNS 资源记录
// ============================================================================

class DnsResourceRecord {
public:
    std::string name;
    DnsRecordType type;
    DnsClass rclass;
    uint32_t ttl;
    uint16_t rdlength;
    std::vector<uint8_t> rdata_raw;  // 原始 RDATA

    // 解析后的 RDATA（根据类型）
    bool rdata_parsed;

    // 使用 shared_ptr 避免大量拷贝
    std::shared_ptr<ARdata> a_rdata;
    std::shared_ptr<AAAARdata> aaaa_rdata;
    std::shared_ptr<DomainRdata> domain_rdata;  // CNAME/NS/PTR
    std::shared_ptr<MXRdata> mx_rdata;
    std::shared_ptr<TXTRdata> txt_rdata;
    std::shared_ptr<SOARdata> soa_rdata;
    std::shared_ptr<SRVRdata> srv_rdata;
    std::shared_ptr<RawRdata> raw_rdata;

    DnsResourceRecord()
        : type(DnsRecordType::A), rclass(DnsClass::IN)
        , ttl(0), rdlength(0), rdata_parsed(false)
    {}

    std::string to_string() const;
    std::string rdata_to_string() const;

    // 便捷访问方法
    std::string get_ip_address() const;  // A 或 AAAA
    std::string get_domain() const;      // CNAME/NS/PTR
};

// ============================================================================
// DNS 消息
// ============================================================================

class DnsMessage {
public:
    // DNS 头部
    uint16_t id;
    DnsFlags flags;

    // 计数字段
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;

    // DNS 各部分
    std::vector<DnsQuestion> questions;
    std::vector<DnsResourceRecord> answers;
    std::vector<DnsResourceRecord> authorities;
    std::vector<DnsResourceRecord> additionals;

    DnsMessage()
        : id(0), qd_count(0), an_count(0), ns_count(0), ar_count(0)
    {}

    // 便捷方法
    bool is_query() const { return !flags.qr; }
    bool is_response() const { return flags.qr; }
    DnsResponseCode response_code() const { return flags.rcode; }

    std::vector<std::string> get_queried_domains() const;
    std::vector<std::string> get_resolved_ips() const;
    std::vector<std::string> get_all_domains() const;

    std::string to_string() const;
};

// ============================================================================
// DNS 解析器
// ============================================================================

class DnsParser {
public:
    // 解析 DNS 消息
    static int parse_message(const uint8_t* data, size_t len, DnsMessage& message);

    // 辅助函数
    static std::string record_type_to_string(DnsRecordType type);
    static std::string class_to_string(DnsClass cls);
    static std::string opcode_to_string(DnsOpcode opcode);
    static std::string rcode_to_string(DnsResponseCode rcode);

private:
    // 解析域名（处理压缩）
    static std::string parse_domain_name(const uint8_t* msg_start, size_t msg_len,
                                        size_t& offset);

    // 解析 DNS 头部
    static bool parse_header(const uint8_t* data, size_t len, DnsMessage& message);

    // 解析问题部分
    static bool parse_question(const uint8_t* msg_start, size_t msg_len,
                              size_t& offset, DnsQuestion& question);

    // 解析资源记录
    static bool parse_resource_record(const uint8_t* msg_start, size_t msg_len,
                                     size_t& offset, DnsResourceRecord& rr);

    // 解析 RDATA
    static void parse_rdata(const uint8_t* msg_start, size_t msg_len,
                           DnsResourceRecord& rr, size_t rdata_offset);

    // 具体 RDATA 解析器
    static std::shared_ptr<ARdata> parse_a_rdata(const uint8_t* rdata, uint16_t rdlength);
    static std::shared_ptr<AAAARdata> parse_aaaa_rdata(const uint8_t* rdata, uint16_t rdlength);
    static std::shared_ptr<DomainRdata> parse_domain_rdata(
        const uint8_t* msg_start, size_t msg_len, size_t rdata_offset, uint16_t rdlength);
    static std::shared_ptr<MXRdata> parse_mx_rdata(
        const uint8_t* msg_start, size_t msg_len, size_t rdata_offset, uint16_t rdlength);
    static std::shared_ptr<TXTRdata> parse_txt_rdata(const uint8_t* rdata, uint16_t rdlength);
    static std::shared_ptr<SOARdata> parse_soa_rdata(
        const uint8_t* msg_start, size_t msg_len, size_t rdata_offset, uint16_t rdlength);
    static std::shared_ptr<SRVRdata> parse_srv_rdata(
        const uint8_t* msg_start, size_t msg_len, size_t rdata_offset, uint16_t rdlength);
};

} // namespace decoders
} // namespace netguardian

#endif // NETGUARDIAN_DECODERS_DNS_PARSER_H
