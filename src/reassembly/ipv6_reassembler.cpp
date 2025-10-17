#include "reassembly/ipv6_reassembler.h"
#include <cstring>

namespace netguardian {
namespace reassembly {

bool Ipv6Reassembler::add_fragment(const Ipv6FragmentKey& key,
                                   uint16_t fragment_offset,
                                   const uint8_t* data,
                                   uint16_t data_len,
                                   bool more_fragments) {
    if (!data || data_len == 0) {
        return false;
    }

    stats_.total_fragments++;

    auto now = std::chrono::system_clock::now();
    auto* frag = IpFragment::create(fragment_offset, data, data_len, more_fragments, now);
    if (!frag) {
        return false;
    }

    auto& list = fragment_cache_[key];
    if (!list.head) {
        list.first_seen = now;
    }

    if (stats_.active_fragments >= max_fragments_) {
        frag->destroy();
        return false;
    }

    if (!more_fragments) {
        list.has_last_fragment = true;
        list.total_length = fragment_offset + data_len;
    }

    insert_fragment(list, frag);
    stats_.active_fragments++;

    return true;
}

void Ipv6Reassembler::insert_fragment(FragmentList& list, IpFragment* new_frag) {
    if (!list.head) {
        list.head = list.tail = new_frag;
        return;
    }

    IpFragment* cur = list.head;
    IpFragment* prev = nullptr;

    while (cur) {
        if (new_frag->offset() < cur->offset()) {
            break;
        }

        if (new_frag->overlaps_with(cur)) {
            stats_.overlap_count++;
            new_frag->destroy();
            stats_.active_fragments--;
            return;
        }

        prev = cur;
        cur = cur->next();
    }

    if (!prev) {
        new_frag->set_next(list.head);
        list.head->set_prev(new_frag);
        list.head = new_frag;
        stats_.out_of_order_count++;
    } else {
        new_frag->set_prev(prev);
        new_frag->set_next(cur);
        prev->set_next(new_frag);
        if (cur) {
            cur->set_prev(new_frag);
            stats_.out_of_order_count++;
        } else {
            list.tail = new_frag;
        }
    }
}

bool Ipv6Reassembler::can_reassemble(const Ipv6FragmentKey& key) const {
    auto it = fragment_cache_.find(key);
    if (it == fragment_cache_.end()) {
        return false;
    }

    return is_complete(it->second);
}

bool Ipv6Reassembler::is_complete(const FragmentList& list) const {
    if (!list.head || !list.has_last_fragment) {
        return false;
    }

    uint16_t expected_offset = 0;
    IpFragment* cur = list.head;

    while (cur) {
        if (cur->offset() > expected_offset) {
            return false;
        }

        expected_offset = cur->end_offset();
        cur = cur->next();
    }

    return expected_offset >= list.total_length;
}

std::vector<uint8_t> Ipv6Reassembler::reassemble(const Ipv6FragmentKey& key) {
    std::vector<uint8_t> result;

    auto it = fragment_cache_.find(key);
    if (it == fragment_cache_.end()) {
        return result;
    }

    FragmentList& list = it->second;

    if (!is_complete(list)) {
        return result;
    }

    result.reserve(list.total_length);

    IpFragment* cur = list.head;
    while (cur) {
        result.insert(result.end(), cur->data(), cur->data() + cur->length());
        cur = cur->next();
    }

    clear_fragments(list);
    fragment_cache_.erase(it);

    stats_.reassembled_packets++;

    return result;
}

void Ipv6Reassembler::cleanup_timeout() {
    auto now = std::chrono::system_clock::now();
    auto timeout = std::chrono::seconds(timeout_seconds_);

    for (auto it = fragment_cache_.begin(); it != fragment_cache_.end(); ) {
        auto& list = it->second;

        if ((now - list.first_seen) > timeout) {
            clear_fragments(list);
            it = fragment_cache_.erase(it);
            stats_.timeout_count++;
        } else {
            ++it;
        }
    }
}

void Ipv6Reassembler::clear_fragments(FragmentList& list) {
    IpFragment* cur = list.head;
    while (cur) {
        IpFragment* next = cur->next();
        cur->destroy();
        stats_.active_fragments--;
        cur = next;
    }

    list.head = nullptr;
    list.tail = nullptr;
}

void Ipv6Reassembler::clear_all() {
    for (auto& pair : fragment_cache_) {
        clear_fragments(pair.second);
    }
    fragment_cache_.clear();
}

} // namespace reassembly
} // namespace netguardian
