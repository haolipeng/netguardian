#ifndef NETGUARDIAN_DECODERS_DNS_TRANSACTION_H
#define NETGUARDIAN_DECODERS_DNS_TRANSACTION_H

#include "decoders/dns_parser.h"
#include <chrono>
#include <unordered_map>
#include <memory>
#include <string>

namespace netguardian {
namespace decoders {

using time_point = std::chrono::system_clock::time_point;

// ============================================================================
// DNS 事务
// ============================================================================

struct DnsTransaction {
    uint16_t transaction_id;
    std::string client_ip;
    uint16_t client_port;
    std::string server_ip;
    uint16_t server_port;

    time_point query_time;
    time_point response_time;

    std::shared_ptr<DnsMessage> query;
    std::shared_ptr<DnsMessage> response;

    bool has_response;
    uint64_t rtt_microseconds;  // Round-trip time in microseconds

    DnsTransaction()
        : transaction_id(0), client_port(0), server_port(53)
        , has_response(false), rtt_microseconds(0)
    {}

    std::string to_string() const;
    double rtt_milliseconds() const {
        return rtt_microseconds / 1000.0;
    }
};

// ============================================================================
// DNS 事务跟踪器
// ============================================================================

class DnsTransactionTracker {
public:
    explicit DnsTransactionTracker(uint32_t timeout_seconds = 30)
        : timeout_seconds_(timeout_seconds)
    {}

    // 添加查询
    void add_query(std::shared_ptr<DnsMessage> query,
                   const std::string& src_ip, uint16_t src_port,
                   const std::string& dst_ip, uint16_t dst_port = 53);

    // 添加响应（如果找到匹配的查询，返回 true）
    bool add_response(std::shared_ptr<DnsMessage> response,
                     const std::string& src_ip, uint16_t src_port,
                     const std::string& dst_ip, uint16_t dst_port);

    // 获取已完成的事务
    std::vector<DnsTransaction> get_completed_transactions();

    // 清理超时的查询
    void cleanup_expired();

    // 统计信息
    size_t pending_count() const { return pending_.size(); }
    size_t completed_count() const { return completed_.size(); }

    // 获取统计数据
    struct Statistics {
        size_t total_queries;
        size_t total_responses;
        size_t total_matched;
        size_t total_timeout;
        double avg_rtt_ms;
        double min_rtt_ms;
        double max_rtt_ms;

        Statistics()
            : total_queries(0), total_responses(0), total_matched(0)
            , total_timeout(0), avg_rtt_ms(0.0)
            , min_rtt_ms(0.0), max_rtt_ms(0.0)
        {}

        std::string to_string() const;
    };

    Statistics get_statistics() const;

private:
    uint32_t timeout_seconds_;

    // 待匹配的查询（Key: id + client_ip + client_port）
    std::unordered_map<std::string, DnsTransaction> pending_;

    // 已完成的事务
    std::vector<DnsTransaction> completed_;

    // 统计信息
    mutable Statistics stats_;

    // 生成唯一键
    std::string make_key(uint16_t id, const std::string& client_ip, uint16_t client_port) const;

    // 更新统计信息
    void update_statistics(const DnsTransaction& trans);
};

} // namespace decoders
} // namespace netguardian

#endif // NETGUARDIAN_DECODERS_DNS_TRANSACTION_H
