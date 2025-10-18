#ifndef NETGUARDIAN_CORE_FLOW_H
#define NETGUARDIAN_CORE_FLOW_H

#include <cstdint>
#include <array>
#include <chrono>
#include <memory>
#include <string>

namespace netguardian {
namespace core {

/**
 * Flow key for tracking network connections
 */
struct FlowKey {
    std::array<uint8_t, 16> src_ip;
    std::array<uint8_t, 16> dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t ip_version;  // 4 or 6

    bool operator==(const FlowKey& other) const;
    bool operator<(const FlowKey& other) const;
};

/**
 * Flow statistics
 */
struct FlowStats {
    uint64_t packets_to_server;
    uint64_t packets_to_client;
    uint64_t bytes_to_server;
    uint64_t bytes_to_client;

    FlowStats()
        : packets_to_server(0)
        , packets_to_client(0)
        , bytes_to_server(0)
        , bytes_to_client(0)
    {}
};

/**
 * Network flow representing a bidirectional connection
 */
class Flow {
public:
    using TimePoint = std::chrono::system_clock::time_point;

    enum class State {
        NEW,
        ESTABLISHED,
        CLOSING,
        CLOSED
    };

    explicit Flow(const FlowKey& key);
    ~Flow();

    const FlowKey& key() const { return key_; }
    State state() const { return state_; }
    void set_state(State state) { state_ = state; }

    const FlowStats& stats() const { return stats_; }
    FlowStats& stats() { return stats_; }

    TimePoint start_time() const { return start_time_; }
    TimePoint last_seen() const { return last_seen_; }
    void update_last_seen() { last_seen_ = std::chrono::system_clock::now(); }

    // Application layer protocol
    void set_app_protocol(const std::string& protocol) { app_protocol_ = protocol; }
    const std::string& app_protocol() const { return app_protocol_; }

    // Flow timeout check
    bool is_expired(std::chrono::seconds timeout) const;

private:
    FlowKey key_;
    State state_;
    FlowStats stats_;
    TimePoint start_time_;
    TimePoint last_seen_;
    std::string app_protocol_;
};

using FlowPtr = std::shared_ptr<Flow>;

} // namespace core
} // namespace netguardian

#endif // NETGUARDIAN_CORE_FLOW_H
