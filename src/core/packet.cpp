#include "core/packet.h"
#include <cstring>
#include <new>

namespace netguardian {
namespace core {

Packet::Packet()
    : data_(nullptr)
    , length_(0)
    , caplen_(0)
    , timestamp_(std::chrono::system_clock::now())
    , interface_id_(0)
    , decoded_(false)
    , protocol_stack_()
    , eth_offset_(0)
    , ip_offset_(0)
    , transport_offset_(0)
    , payload_offset_(0)
{
}

Packet::~Packet() {
    if (data_) {
        delete[] data_;
        data_ = nullptr;
    }
}

Packet::Packet(const Packet& other)
    : data_(nullptr)
    , length_(other.length_)
    , caplen_(other.caplen_)
    , timestamp_(other.timestamp_)
    , interface_id_(other.interface_id_)
    , decoded_(other.decoded_)
    , protocol_stack_(other.protocol_stack_)
    , eth_offset_(other.eth_offset_)
    , ip_offset_(other.ip_offset_)
    , transport_offset_(other.transport_offset_)
    , payload_offset_(other.payload_offset_)
{
    // Deep copy of data buffer
    if (other.data_ && other.length_ > 0) {
        data_ = new uint8_t[other.length_];
        std::memcpy(data_, other.data_, other.length_);
    }
}

Packet& Packet::operator=(const Packet& other) {
    if (this != &other) {
        // Delete old data
        if (data_) {
            delete[] data_;
            data_ = nullptr;
        }

        // Copy fields
        length_ = other.length_;
        caplen_ = other.caplen_;
        timestamp_ = other.timestamp_;
        interface_id_ = other.interface_id_;
        decoded_ = other.decoded_;
        protocol_stack_ = other.protocol_stack_;
        eth_offset_ = other.eth_offset_;
        ip_offset_ = other.ip_offset_;
        transport_offset_ = other.transport_offset_;
        payload_offset_ = other.payload_offset_;

        // Deep copy of data buffer
        if (other.data_ && other.length_ > 0) {
            data_ = new uint8_t[other.length_];
            std::memcpy(data_, other.data_, other.length_);
        }
    }
    return *this;
}

void Packet::reset() {
    length_ = 0;
    caplen_ = 0;
    timestamp_ = std::chrono::system_clock::now();
    interface_id_ = 0;
    decoded_ = false;
    protocol_stack_ = ProtocolStack();
    eth_offset_ = 0;
    ip_offset_ = 0;
    transport_offset_ = 0;
    payload_offset_ = 0;
}

bool Packet::allocate(size_t size) {
    if (data_) {
        delete[] data_;
    }

    try {
        data_ = new uint8_t[size];
        length_ = size;
        caplen_ = size;
        return true;
    } catch (const std::bad_alloc&) {
        data_ = nullptr;
        length_ = 0;
        caplen_ = 0;
        return false;
    }
}

} // namespace core
} // namespace netguardian
