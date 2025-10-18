#include "core/packet_capture.h"
#include <cstring>
#include <iostream>
#include <arpa/inet.h>

namespace netguardian {
namespace core {

PacketCapture::PacketCapture(const CaptureConfig& config)
    : config_(config)
    , pcap_handle_(nullptr)
    , callback_(nullptr)
    , user_data_(nullptr)
    , running_(false)
    , error_msg_("")
    , stats_()
{
}

PacketCapture::~PacketCapture() {
    stop();
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
}

bool PacketCapture::start() {
    if (running_) {
        error_msg_ = "Capture already running";
        return false;
    }

    // Determine capture mode
    bool success = false;
    if (!config_.pcap_file.empty()) {
        // Offline mode - read from PCAP file
        success = init_offline_capture();
    } else if (!config_.interface.empty()) {
        // Live mode - capture from interface
        success = init_live_capture();
    } else {
        error_msg_ = "No interface or PCAP file specified";
        return false;
    }

    if (!success) {
        return false;
    }

    // Apply BPF filter if specified
    if (!config_.filter.empty()) {
        if (!apply_filter()) {
            pcap_close(pcap_handle_);
            pcap_handle_ = nullptr;
            return false;
        }
    }

    running_ = true;
    return true;
}

void PacketCapture::stop() {
    if (running_) {
        running_ = false;
        if (pcap_handle_) {
            pcap_breakloop(pcap_handle_);
        }
    }
}

bool PacketCapture::init_live_capture() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open live capture
    pcap_handle_ = pcap_open_live(
        config_.interface.c_str(),
        config_.snaplen,
        config_.promiscuous ? 1 : 0,
        config_.timeout_ms,
        errbuf
    );

    if (!pcap_handle_) {
        error_msg_ = std::string("Failed to open interface ") +
                     config_.interface + ": " + errbuf;
        return false;
    }

    // Set buffer size
    if (pcap_set_buffer_size(pcap_handle_, config_.buffer_size) != 0) {
        error_msg_ = "Failed to set buffer size";
        // Non-fatal, continue
    }

    return true;
}

bool PacketCapture::init_offline_capture() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open PCAP file
    pcap_handle_ = pcap_open_offline(config_.pcap_file.c_str(), errbuf);

    if (!pcap_handle_) {
        error_msg_ = std::string("Failed to open PCAP file ") +
                     config_.pcap_file + ": " + errbuf;
        return false;
    }

    return true;
}

bool PacketCapture::apply_filter() {
    if (!pcap_handle_) {
        error_msg_ = "No active capture handle";
        return false;
    }

    struct bpf_program fp;
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;

    // Get network and netmask for live capture
    if (config_.pcap_file.empty() && !config_.interface.empty()) {
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_lookupnet(config_.interface.c_str(), &net, &mask, errbuf) == -1) {
            // Non-fatal, use 0
            net = 0;
            mask = 0;
        }
    }

    // Compile filter
    if (pcap_compile(pcap_handle_, &fp, config_.filter.c_str(), 1, mask) == -1) {
        error_msg_ = std::string("Failed to compile filter: ") +
                     pcap_geterr(pcap_handle_);
        return false;
    }

    // Apply filter
    if (pcap_setfilter(pcap_handle_, &fp) == -1) {
        error_msg_ = std::string("Failed to set filter: ") +
                     pcap_geterr(pcap_handle_);
        pcap_freecode(&fp);
        return false;
    }

    pcap_freecode(&fp);
    return true;
}

void PacketCapture::set_callback(PacketCallback callback, void* user_data) {
    callback_ = callback;
    user_data_ = user_data;
}

void PacketCapture::pcap_handler(u_char* user, const struct pcap_pkthdr* header,
                                 const u_char* bytes) {
    PacketCapture* capture = reinterpret_cast<PacketCapture*>(user);

    if (!capture || !capture->callback_) {
        return;
    }

    // Create packet object
    Packet packet;

    // Allocate and copy packet data
    if (!packet.allocate(header->caplen)) {
        return;
    }

    std::memcpy(packet.data(), bytes, header->caplen);

    // Set packet metadata
    auto ts = std::chrono::system_clock::from_time_t(header->ts.tv_sec);
    ts += std::chrono::microseconds(header->ts.tv_usec);
    packet.set_timestamp(ts);

    // Update statistics
    capture->stats_.packets_received++;
    capture->stats_.bytes_received += header->len;

    // Call user callback
    capture->callback_(packet, capture->user_data_);
}

int PacketCapture::loop(int count) {
    if (!running_ || !pcap_handle_) {
        error_msg_ = "Capture not started";
        return -1;
    }

    if (!callback_) {
        error_msg_ = "No callback set";
        return -1;
    }

    int result = pcap_loop(pcap_handle_, count, pcap_handler,
                          reinterpret_cast<u_char*>(this));

    if (result == -1) {
        error_msg_ = std::string("pcap_loop error: ") + pcap_geterr(pcap_handle_);
        return -1;
    }

    return result;
}

int PacketCapture::dispatch_one() {
    if (!running_ || !pcap_handle_) {
        error_msg_ = "Capture not started";
        return -1;
    }

    if (!callback_) {
        error_msg_ = "No callback set";
        return -1;
    }

    int result = pcap_dispatch(pcap_handle_, 1, pcap_handler,
                              reinterpret_cast<u_char*>(this));

    if (result == -1) {
        error_msg_ = std::string("pcap_dispatch error: ") + pcap_geterr(pcap_handle_);
        return -1;
    }

    return result;
}

bool PacketCapture::get_stats(CaptureStats* stats) const {
    if (!stats) {
        return false;
    }

    // Copy internal stats
    *stats = stats_;

    // Get pcap stats if available (live capture only)
    if (pcap_handle_ && config_.pcap_file.empty()) {
        struct pcap_stat ps;
        if (pcap_stats(pcap_handle_, &ps) == 0) {
            stats->packets_dropped = ps.ps_drop;
            stats->packets_dropped_if = ps.ps_ifdrop;
        }
    }

    return true;
}

int PacketCapture::get_datalink() const {
    if (!pcap_handle_) {
        return -1;
    }
    return pcap_datalink(pcap_handle_);
}

int PacketCapture::get_snaplen() const {
    if (!pcap_handle_) {
        return -1;
    }
    return pcap_snapshot(pcap_handle_);
}

bool PacketCapture::list_interfaces(std::vector<std::string>& interfaces) {
    interfaces.clear();

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return false;
    }

    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        if (dev->name) {
            interfaces.push_back(dev->name);
        }
    }

    pcap_freealldevs(alldevs);
    return true;
}

} // namespace core
} // namespace netguardian
