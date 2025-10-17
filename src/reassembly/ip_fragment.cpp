#include "reassembly/ip_fragment.h"
#include <cstring>

namespace netguardian {
namespace reassembly {

IpFragment* IpFragment::create(uint16_t offset, const uint8_t* data, uint16_t len,
                               bool more_fragments,
                               const std::chrono::system_clock::time_point& timestamp) {
    if (!data || len == 0) {
        return nullptr;
    }

    auto* frag = new IpFragment(offset, len, more_fragments, timestamp);

    // 分配并复制数据
    frag->data_ = new uint8_t[len];
    std::memcpy(frag->data_, data, len);

    return frag;
}

void IpFragment::destroy() {
    delete this;
}

} // namespace reassembly
} // namespace netguardian
