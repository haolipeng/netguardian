#include "core/flow.h"
#include <algorithm>

namespace netguardian {
namespace core {

bool FlowKey::operator==(const FlowKey& other) const {
    return src_ip == other.src_ip &&
           dst_ip == other.dst_ip &&
           src_port == other.src_port &&
           dst_port == other.dst_port &&
           protocol == other.protocol &&
           ip_version == other.ip_version;
}

bool FlowKey::operator<(const FlowKey& other) const {
    if (src_ip != other.src_ip) return src_ip < other.src_ip;
    if (dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
    if (src_port != other.src_port) return src_port < other.src_port;
    if (dst_port != other.dst_port) return dst_port < other.dst_port;
    if (protocol != other.protocol) return protocol < other.protocol;
    return ip_version < other.ip_version;
}

Flow::Flow(const FlowKey& key)
    : key_(key)
    , state_(State::NEW)
    , stats_()
    , start_time_(std::chrono::system_clock::now())
    , last_seen_(start_time_)
    , app_protocol_("unknown")
{
}

Flow::~Flow() {
}

bool Flow::is_expired(std::chrono::seconds timeout) const {
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_seen_);
    return elapsed >= timeout;
}

} // namespace core
} // namespace netguardian
