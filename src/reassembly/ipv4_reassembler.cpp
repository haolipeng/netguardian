#include "reassembly/ipv4_reassembler.h"
#include <cstring>
#include <algorithm>

namespace netguardian {
namespace reassembly {

bool Ipv4Reassembler::add_fragment(const Ipv4FragmentKey& key,
                                   uint16_t fragment_offset,
                                   const uint8_t* data,
                                   uint16_t data_len,
                                   bool more_fragments) {
    if (!data || data_len == 0) {
        return false;
    }

    // 统计
    stats_.total_fragments++;

    // 创建分片节点
    auto now = std::chrono::system_clock::now();
    auto* frag = IpFragment::create(fragment_offset, data, data_len, more_fragments, now);
    if (!frag) {
        return false;
    }

    // 获取或创建分片链表
    auto& list = fragment_cache_[key];
    if (!list.head) {
        list.first_seen = now;
    }

    // 检查是否超过最大分片数限制
    if (stats_.active_fragments >= max_fragments_) {
        frag->destroy();
        return false;
    }

    // 如果这是最后一个分片（MF=0），记录总长度
    if (!more_fragments) {
        list.has_last_fragment = true;
        list.total_length = fragment_offset + data_len;
    }

    // 插入分片到链表
    insert_fragment(list, frag);
    stats_.active_fragments++;

    return true;
}

void Ipv4Reassembler::insert_fragment(FragmentList& list, IpFragment* new_frag) {
    // 空链表
    if (!list.head) {
        list.head = list.tail = new_frag;
        return;
    }

    // 按偏移量查找插入位置
    IpFragment* cur = list.head;
    IpFragment* prev = nullptr;

    while (cur) {
        // 找到插入位置（偏移量 >= 当前节点）
        if (new_frag->offset() < cur->offset()) {
            break;
        }

        // 检查重叠
        if (new_frag->overlaps_with(cur)) {
            stats_.overlap_count++;
            // 简化处理：丢弃新分片（保留先到达的）
            new_frag->destroy();
            stats_.active_fragments--;
            return;
        }

        prev = cur;
        cur = cur->next();
    }

    // 插入到 prev 和 cur 之间
    if (!prev) {
        // 插入到头部
        new_frag->set_next(list.head);
        list.head->set_prev(new_frag);
        list.head = new_frag;
        stats_.out_of_order_count++;
    } else {
        // 插入到中间或尾部
        new_frag->set_prev(prev);
        new_frag->set_next(cur);
        prev->set_next(new_frag);
        if (cur) {
            cur->set_prev(new_frag);
            stats_.out_of_order_count++;
        } else {
            // 插入到尾部
            list.tail = new_frag;
        }
    }
}

bool Ipv4Reassembler::can_reassemble(const Ipv4FragmentKey& key) const {
    auto it = fragment_cache_.find(key);
    if (it == fragment_cache_.end()) {
        return false;
    }

    return is_complete(it->second);
}

bool Ipv4Reassembler::is_complete(const FragmentList& list) const {
    if (!list.head || !list.has_last_fragment) {
        return false;
    }

    // 检查是否所有分片都已到达（无空洞）
    uint16_t expected_offset = 0;
    IpFragment* cur = list.head;

    while (cur) {
        // 检查是否有空洞
        if (cur->offset() > expected_offset) {
            return false;  // 有空洞
        }

        expected_offset = cur->end_offset();
        cur = cur->next();
    }

    // 检查是否到达总长度
    return expected_offset >= list.total_length;
}

std::vector<uint8_t> Ipv4Reassembler::reassemble(const Ipv4FragmentKey& key) {
    std::vector<uint8_t> result;

    auto it = fragment_cache_.find(key);
    if (it == fragment_cache_.end()) {
        return result;
    }

    FragmentList& list = it->second;

    // 检查是否可以重组
    if (!is_complete(list)) {
        return result;
    }

    // 分配空间
    result.reserve(list.total_length);

    // 按顺序复制数据
    IpFragment* cur = list.head;
    while (cur) {
        result.insert(result.end(), cur->data(), cur->data() + cur->length());
        cur = cur->next();
    }

    // 清理分片
    clear_fragments(list);
    fragment_cache_.erase(it);

    // 统计
    stats_.reassembled_packets++;

    return result;
}

void Ipv4Reassembler::cleanup_timeout() {
    auto now = std::chrono::system_clock::now();
    auto timeout = std::chrono::seconds(timeout_seconds_);

    // 遍历所有分片链表
    for (auto it = fragment_cache_.begin(); it != fragment_cache_.end(); ) {
        auto& list = it->second;

        // 检查是否超时
        if ((now - list.first_seen) > timeout) {
            clear_fragments(list);
            it = fragment_cache_.erase(it);
            stats_.timeout_count++;
        } else {
            ++it;
        }
    }
}

void Ipv4Reassembler::clear_fragments(FragmentList& list) {
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

void Ipv4Reassembler::clear_all() {
    for (auto& pair : fragment_cache_) {
        clear_fragments(pair.second);
    }
    fragment_cache_.clear();
}

} // namespace reassembly
} // namespace netguardian
