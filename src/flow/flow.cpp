#include "flow/flow.h"

namespace netguardian {
namespace flow {

// 初始化静态成员
std::atomic<uint64_t> Flow::next_flow_id_(1);

} // namespace flow
} // namespace netguardian
