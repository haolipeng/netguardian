#include "decoders/dns_transaction.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <limits>

namespace netguardian {
namespace decoders {

// ============================================================================
// DnsTransaction 实现
// ============================================================================

std::string DnsTransaction::to_string() const {
    std::ostringstream oss;
    oss << "DNS Transaction [ID: " << transaction_id << "]\n";
    oss << "  Client: " << client_ip << ":" << client_port << "\n";
    oss << "  Server: " << server_ip << ":" << server_port << "\n";

    if (query) {
        auto domains = query->get_queried_domains();
        if (!domains.empty()) {
            oss << "  Query: " << domains[0] << "\n";
        }
    }

    if (has_response && response) {
        oss << "  Response: " << DnsParser::rcode_to_string(response->flags.rcode) << "\n";
        auto ips = response->get_resolved_ips();
        if (!ips.empty()) {
            oss << "  Resolved IPs: ";
            for (size_t i = 0; i < ips.size(); i++) {
                if (i > 0) oss << ", ";
                oss << ips[i];
            }
            oss << "\n";
        }
        oss << "  RTT: " << std::fixed << std::setprecision(3)
            << rtt_milliseconds() << " ms\n";
    } else {
        oss << "  Status: No response (timeout or lost)\n";
    }

    return oss.str();
}

// ============================================================================
// DnsTransactionTracker::Statistics 实现
// ============================================================================

std::string DnsTransactionTracker::Statistics::to_string() const {
    std::ostringstream oss;
    oss << "DNS Transaction Statistics:\n";
    oss << "  Total Queries:    " << total_queries << "\n";
    oss << "  Total Responses:  " << total_responses << "\n";
    oss << "  Matched:          " << total_matched << "\n";
    oss << "  Timeout:          " << total_timeout << "\n";

    if (total_matched > 0) {
        oss << "  Average RTT:      " << std::fixed << std::setprecision(3)
            << avg_rtt_ms << " ms\n";
        oss << "  Min RTT:          " << std::fixed << std::setprecision(3)
            << min_rtt_ms << " ms\n";
        oss << "  Max RTT:          " << std::fixed << std::setprecision(3)
            << max_rtt_ms << " ms\n";
    }

    if (total_queries > 0) {
        double match_rate = (double)total_matched / total_queries * 100.0;
        oss << "  Match Rate:       " << std::fixed << std::setprecision(1)
            << match_rate << "%\n";
    }

    return oss.str();
}

// ============================================================================
// DnsTransactionTracker 实现
// ============================================================================

void DnsTransactionTracker::add_query(std::shared_ptr<DnsMessage> query,
                                     const std::string& src_ip, uint16_t src_port,
                                     const std::string& dst_ip, uint16_t dst_port) {
    if (!query || !query->is_query()) {
        return;
    }

    DnsTransaction trans;
    trans.transaction_id = query->id;
    trans.client_ip = src_ip;
    trans.client_port = src_port;
    trans.server_ip = dst_ip;
    trans.server_port = dst_port;
    trans.query_time = std::chrono::system_clock::now();
    trans.query = query;
    trans.has_response = false;

    std::string key = make_key(query->id, src_ip, src_port);
    pending_[key] = trans;

    stats_.total_queries++;
}

bool DnsTransactionTracker::add_response(std::shared_ptr<DnsMessage> response,
                                        const std::string& src_ip, uint16_t src_port,
                                        const std::string& dst_ip, uint16_t dst_port) {
    if (!response || !response->is_response()) {
        return false;
    }

    stats_.total_responses++;

    // 查找匹配的查询
    // 响应: src=server, dst=client
    // 查询: src=client, dst=server
    // 所以响应的 dst_ip:dst_port 应该匹配查询的 client_ip:client_port
    std::string key = make_key(response->id, dst_ip, dst_port);

    auto it = pending_.find(key);
    if (it == pending_.end()) {
        return false;  // 未找到匹配的查询
    }

    // 找到匹配的查询
    DnsTransaction& trans = it->second;
    trans.response = response;
    trans.response_time = std::chrono::system_clock::now();
    trans.has_response = true;

    // 计算 RTT
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
        trans.response_time - trans.query_time);
    trans.rtt_microseconds = duration.count();

    // 移动到已完成列表
    completed_.push_back(trans);
    pending_.erase(it);

    // 更新统计信息
    update_statistics(trans);
    stats_.total_matched++;

    return true;
}

std::vector<DnsTransaction> DnsTransactionTracker::get_completed_transactions() {
    std::vector<DnsTransaction> result = completed_;
    completed_.clear();
    return result;
}

void DnsTransactionTracker::cleanup_expired() {
    auto now = std::chrono::system_clock::now();
    auto timeout = std::chrono::seconds(timeout_seconds_);

    auto it = pending_.begin();
    while (it != pending_.end()) {
        auto age = now - it->second.query_time;
        if (age > timeout) {
            stats_.total_timeout++;
            it = pending_.erase(it);
        } else {
            ++it;
        }
    }
}

DnsTransactionTracker::Statistics DnsTransactionTracker::get_statistics() const {
    return stats_;
}

std::string DnsTransactionTracker::make_key(uint16_t id, const std::string& client_ip,
                                           uint16_t client_port) const {
    std::ostringstream oss;
    oss << id << ":" << client_ip << ":" << client_port;
    return oss.str();
}

void DnsTransactionTracker::update_statistics(const DnsTransaction& trans) {
    double rtt_ms = trans.rtt_milliseconds();

    // 更新平均 RTT
    if (stats_.total_matched == 0) {
        stats_.avg_rtt_ms = rtt_ms;
        stats_.min_rtt_ms = rtt_ms;
        stats_.max_rtt_ms = rtt_ms;
    } else {
        // 累积平均
        stats_.avg_rtt_ms = (stats_.avg_rtt_ms * (stats_.total_matched - 1) + rtt_ms) /
                           stats_.total_matched;

        // 更新最小/最大值
        if (rtt_ms < stats_.min_rtt_ms) {
            stats_.min_rtt_ms = rtt_ms;
        }
        if (rtt_ms > stats_.max_rtt_ms) {
            stats_.max_rtt_ms = rtt_ms;
        }
    }
}

} // namespace decoders
} // namespace netguardian
