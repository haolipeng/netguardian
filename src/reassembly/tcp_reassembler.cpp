#include "reassembly/tcp_reassembler.h"
#include <algorithm>

namespace netguardian {
namespace reassembly {

TcpReassembler::TcpReassembler(OverlapPolicy policy)
    : head_(nullptr)
    , tail_(nullptr)
    , base_seq_(0)
    , next_expected_seq_(0)
    , policy_(policy)
    , max_bytes_(8 * 1024 * 1024)   // 默认 8MB
    , max_segments_(3072)            // 默认 3072 个段
{
}

TcpReassembler::~TcpReassembler() {
    clear();
}

bool TcpReassembler::add_segment(uint32_t seq, const uint8_t* data, uint16_t len) {
    if (len == 0 || data == nullptr) {
        return false;
    }

    // 检查是否超过限制
    if (is_over_limit()) {
        purge_oldest_segments();
    }

    // 创建新段
    auto timestamp = std::chrono::system_clock::now();
    TcpSegment* new_seg = TcpSegment::create(seq, data, len, timestamp);

    if (!new_seg) {
        return false;
    }

    // 如果是第一个段，设置基准序列号
    if (!head_) {
        base_seq_ = seq;
        next_expected_seq_ = seq;
    }

    // 更新统计信息
    stats_.total_segments++;
    stats_.total_bytes += len;

    // 插入段到队列
    insert_segment(new_seg);

    return true;
}

void TcpReassembler::insert_segment(TcpSegment* new_seg) {
    // 空队列，直接插入
    if (!head_) {
        head_ = tail_ = new_seg;
        stats_.active_segments = 1;
        next_expected_seq_ = new_seg->end_seq();
        return;
    }

    // 快速路径：新段正好接在队列末尾（最常见的情况）
    if (SEQ_EQ(tail_->end_seq(), new_seg->start_seq())) {
        tail_->set_next(new_seg);
        new_seg->set_prev(tail_);
        tail_ = new_seg;
        stats_.active_segments++;

        // 如果连续，更新期望序列号
        if (SEQ_EQ(next_expected_seq_, new_seg->start_seq())) {
            next_expected_seq_ = new_seg->end_seq();
        }
        return;
    }

    // 查找插入位置
    TcpSegment* insert_pos = find_insert_position(new_seg->start_seq());

    if (!insert_pos) {
        // 插入到队列头部
        new_seg->set_next(head_);
        head_->set_prev(new_seg);
        head_ = new_seg;
        stats_.active_segments++;

        // 检查是否填补了开头的 gap
        if (SEQ_EQ(new_seg->start_seq(), next_expected_seq_)) {
            // 推进 next_expected_seq
            TcpSegment* cur = new_seg;
            while (cur && SEQ_EQ(next_expected_seq_, cur->start_seq())) {
                next_expected_seq_ = cur->end_seq();
                cur = cur->next();
            }
        } else {
            stats_.out_of_order_count++;
        }
    } else {
        // 插入到 insert_pos 之后
        new_seg->set_next(insert_pos->next());
        new_seg->set_prev(insert_pos);

        if (insert_pos->next()) {
            insert_pos->next()->set_prev(new_seg);
        } else {
            tail_ = new_seg;
        }

        insert_pos->set_next(new_seg);
        stats_.active_segments++;

        // 检查是否填补了 gap
        if (SEQ_EQ(insert_pos->end_seq(), new_seg->start_seq())) {
            // 继续检查后续段
            if (SEQ_EQ(next_expected_seq_, new_seg->start_seq())) {
                TcpSegment* cur = new_seg;
                while (cur && SEQ_EQ(next_expected_seq_, cur->start_seq())) {
                    next_expected_seq_ = cur->end_seq();
                    cur = cur->next();
                }
            }
        } else {
            stats_.out_of_order_count++;
        }
    }

    // 处理重叠
    handle_overlap(new_seg);
}

TcpSegment* TcpReassembler::find_insert_position(uint32_t seq) {
    TcpSegment* cur = head_;
    TcpSegment* prev = nullptr;

    while (cur) {
        // 如果当前段的起始序列号 >= 新段的序列号，插入到当前段之前
        if (SEQ_GEQ(cur->start_seq(), seq)) {
            return prev;
        }

        prev = cur;
        cur = cur->next();
    }

    // 插入到队列末尾
    return prev;
}

void TcpReassembler::handle_overlap(TcpSegment* new_seg) {
    if (!new_seg) return;

    // 检查与前一个段的重叠
    if (new_seg->prev() && new_seg->prev()->overlaps_with(new_seg)) {
        stats_.overlap_count++;

        // 根据策略处理重叠
        if (policy_ == OverlapPolicy::FIRST) {
            // 保留先到的数据，截断新段
            TcpSegment* prev = new_seg->prev();
            if (SEQ_GEQ(prev->end_seq(), new_seg->end_seq())) {
                // 新段完全被覆盖，删除新段
                remove_segment(new_seg);
                new_seg->destroy();
                return;
            }
            // 部分重叠，截断新段的开头（这里简化处理，不修改数据）
        }
        // LAST 策略：保留后到的数据，这里简化为允许重叠
    }

    // 检查与后一个段的重叠
    if (new_seg->next() && new_seg->overlaps_with(new_seg->next())) {
        stats_.overlap_count++;

        if (policy_ == OverlapPolicy::FIRST) {
            // 保留先到的数据（新段），截断或删除后面的段
            TcpSegment* next = new_seg->next();
            if (SEQ_GEQ(new_seg->end_seq(), next->end_seq())) {
                // 后面的段完全被覆盖，删除它
                TcpSegment* to_remove = next;
                remove_segment(to_remove);
                to_remove->destroy();
            }
        }
    }
}

void TcpReassembler::remove_segment(TcpSegment* seg) {
    if (!seg) return;

    if (seg->prev()) {
        seg->prev()->set_next(seg->next());
    } else {
        head_ = seg->next();
    }

    if (seg->next()) {
        seg->next()->set_prev(seg->prev());
    } else {
        tail_ = seg->prev();
    }

    stats_.active_segments--;
}

std::vector<uint8_t> TcpReassembler::get_reassembled_data(uint32_t& next_seq) {
    std::vector<uint8_t> result;
    next_seq = next_expected_seq_;

    if (!head_) {
        return result;
    }

    // 只返回从 base_seq 开始的连续数据
    TcpSegment* cur = head_;

    // 跳过已经处理过的段（序列号 < base_seq）
    while (cur && SEQ_LT(cur->end_seq(), base_seq_)) {
        TcpSegment* to_remove = cur;
        cur = cur->next();
        remove_segment(to_remove);
        to_remove->destroy();
    }

    if (!cur) {
        return result;
    }

    // 收集连续的数据
    uint32_t expected_seq = base_seq_;

    while (cur) {
        // 检查是否有 gap
        if (SEQ_GT(cur->start_seq(), expected_seq)) {
            // 有 gap，停止
            stats_.gap_count++;
            break;
        }

        // 计算需要复制的数据范围
        uint32_t data_start = 0;
        uint32_t data_len = cur->length();

        // 如果段的起始序列号 < expected_seq，需要跳过部分数据
        if (SEQ_LT(cur->start_seq(), expected_seq)) {
            data_start = expected_seq - cur->start_seq();
            if (data_start >= cur->length()) {
                // 整个段都已经处理过了
                cur = cur->next();
                continue;
            }
            data_len = cur->length() - data_start;
        }

        // 复制数据
        const uint8_t* src = cur->data() + data_start;
        result.insert(result.end(), src, src + data_len);

        expected_seq = cur->end_seq();
        stats_.reassembled_bytes += data_len;

        cur = cur->next();
    }

    next_seq = expected_seq;
    return result;
}

void TcpReassembler::purge_acked_data(uint32_t ack_seq) {
    TcpSegment* cur = head_;

    while (cur && SEQ_LEQ(cur->end_seq(), ack_seq)) {
        TcpSegment* to_remove = cur;
        cur = cur->next();
        remove_segment(to_remove);
        to_remove->destroy();
    }

    // 更新 base_seq
    if (head_) {
        base_seq_ = head_->start_seq();
    } else {
        base_seq_ = ack_seq;
    }
}

void TcpReassembler::clear() {
    TcpSegment* cur = head_;

    while (cur) {
        TcpSegment* next = cur->next();
        cur->destroy();
        cur = next;
    }

    head_ = tail_ = nullptr;
    stats_.active_segments = 0;
}

bool TcpReassembler::has_contiguous_data() const {
    if (!head_) {
        return false;
    }

    // 检查从 head 开始是否有连续数据
    return SEQ_LEQ(head_->start_seq(), next_expected_seq_);
}

bool TcpReassembler::is_over_limit() const {
    return stats_.active_segments >= max_segments_ ||
           stats_.total_bytes >= max_bytes_;
}

void TcpReassembler::purge_oldest_segments() {
    // 简单策略：删除队列头部的段
    if (head_) {
        TcpSegment* to_remove = head_;
        remove_segment(to_remove);
        to_remove->destroy();

        if (head_) {
            base_seq_ = head_->start_seq();
        }
    }
}

} // namespace reassembly
} // namespace netguardian
