#include "reassembly/tcp_segment.h"
#include <cstdlib>

namespace netguardian {
namespace reassembly {

TcpSegment::TcpSegment(uint32_t seq, const uint8_t* data, uint16_t len,
                       const std::chrono::system_clock::time_point& timestamp)
    : seq_(seq)
    , length_(len)
    , data_(nullptr)
    , timestamp_(timestamp)
    , prev_(nullptr)
    , next_(nullptr)
{
    if (len > 0 && data) {
        data_ = new uint8_t[len];
        std::memcpy(data_, data, len);
    }
}

TcpSegment::~TcpSegment() {
    if (data_) {
        delete[] data_;
        data_ = nullptr;
    }
}

TcpSegment* TcpSegment::create(uint32_t seq, const uint8_t* data, uint16_t len,
                               const std::chrono::system_clock::time_point& timestamp) {
    return new TcpSegment(seq, data, len, timestamp);
}

void TcpSegment::destroy() {
    delete this;
}

} // namespace reassembly
} // namespace netguardian
