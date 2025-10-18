#include "core/mt_detection_engine.h"
#include "decoders/ipv4_decoder.h"
#include "decoders/tcp_decoder.h"
#include "decoders/udp_decoder.h"
#include <iostream>
#include <chrono>

namespace netguardian {
namespace core {

// 从数据包中提取流键
static flow::FlowKey extract_flow_key(const Packet& packet) {
    using namespace decoders;

    flow::FlowKey key;
    const auto& stack = packet.protocol_stack();

    // 提取 IP 地址
    if (stack.l3_type == ProtocolType::IPV4 &&
        static_cast<size_t>(stack.l3_offset) + sizeof(IPv4Header) <= packet.length()) {

        const IPv4Header* ip_hdr = reinterpret_cast<const IPv4Header*>(
            packet.data() + stack.l3_offset
        );

        key.src_ip = ip_hdr->src_ip;
        key.dst_ip = ip_hdr->dst_ip;
        key.protocol = ip_hdr->protocol;
    }

    // 提取端口（TCP/UDP）
    if (stack.l4_type == ProtocolType::TCP &&
        static_cast<size_t>(stack.l4_offset) + sizeof(TcpHeader) <= packet.length()) {

        const TcpHeader* tcp_hdr = reinterpret_cast<const TcpHeader*>(
            packet.data() + stack.l4_offset
        );

        key.src_port = ntohs(tcp_hdr->src_port);
        key.dst_port = ntohs(tcp_hdr->dst_port);

    } else if (stack.l4_type == ProtocolType::UDP &&
               static_cast<size_t>(stack.l4_offset) + sizeof(UdpHeader) <= packet.length()) {

        const UdpHeader* udp_hdr = reinterpret_cast<const UdpHeader*>(
            packet.data() + stack.l4_offset
        );

        key.src_port = ntohs(udp_hdr->src_port);
        key.dst_port = ntohs(udp_hdr->dst_port);
    }

    return key;
}

MTDetectionEngine::MTDetectionEngine(const MTDetectionEngineConfig& config)
    : config_(config)
    , packet_queue_(config.queue_size)
{
    // 确定工作线程数量
    if (config_.num_worker_threads == 0) {
        num_workers_ = std::thread::hardware_concurrency();
        if (num_workers_ > 1) {
            num_workers_ -= 1;  // 留一个核心给捕获线程
        }
        if (num_workers_ == 0) {
            num_workers_ = 2;  // 最少2个
        }
    } else {
        num_workers_ = config_.num_worker_threads;
    }

    std::cout << "[INFO] MT Detection Engine configured with " << num_workers_ << " worker threads\n";
}

MTDetectionEngine::~MTDetectionEngine() {
    if (running_) {
        stop();
    }
}

bool MTDetectionEngine::initialize() {
    if (initialized_) {
        std::cerr << "[ERROR] Detection engine already initialized\n";
        return false;
    }

    std::cout << "[INFO] Initializing MT detection engine...\n";

    try {
        // 创建并发流表
        flow_table_ = std::make_unique<flow::ConcurrentFlowTable>(
            config_.flow_table_shards,
            config_.flow_config.max_flows / config_.flow_table_shards
        );
        flow_manager_ = std::make_unique<flow::FlowManager>(*flow_table_, config_.flow_timeout);
        std::cout << "  ✓ Concurrent flow table initialized (" << config_.flow_table_shards << " shards)\n";

        // 初始化规则引擎
        rule_manager_ = std::make_unique<rules::RuleManager>();
        if (!config_.rules_path.empty()) {
            if (rule_manager_->load_rules_file(config_.rules_path)) {
                std::cout << "  ✓ Loaded " << rule_manager_->size() << " rules\n";
            } else {
                std::cerr << "  [WARN] Failed to load rules from " << config_.rules_path << "\n";
            }
        }

        // 初始化告警系统
        alert_generator_ = std::make_unique<alerts::AlertGenerator>();
        alert_manager_ = std::make_unique<alerts::AlertManager>();
        alert_manager_->set_deduplication_config(config_.alert_dedup_config);

        if (config_.alert_console_output) {
            auto console_output = std::make_shared<alerts::ConsoleAlertOutput>(
                alerts::ConsoleAlertOutput::ColorMode::BASIC
            );
            alert_manager_->add_output(console_output);
        }

        if (config_.alert_file_output && !config_.alert_output_path.empty()) {
            auto file_output = std::make_shared<alerts::FileAlertOutput>(
                config_.alert_output_path,
                config_.alert_output_format
            );
            alert_manager_->add_output(file_output);
        }

        std::cout << "  ✓ Alert system initialized\n";

        // 为每个工作线程初始化组件
        worker_components_.resize(num_workers_);
        for (size_t i = 0; i < num_workers_; ++i) {
            auto& comp = worker_components_[i];

            // 解码器（每个线程独立）
            comp.eth_decoder = std::make_unique<decoders::EthernetDecoder>();
            comp.ipv4_decoder = std::make_unique<decoders::IPv4Decoder>();
            comp.tcp_decoder = std::make_unique<decoders::TcpDecoder>();
            comp.udp_decoder = std::make_unique<decoders::UdpDecoder>();

            // L7 解析器
            if (config_.enable_http_parser) {
                comp.http_parser = std::make_unique<decoders::HttpParser>();
            }
            if (config_.enable_dns_parser) {
                comp.dns_parser = std::make_unique<decoders::DnsParser>();
            }

            // 重组引擎
            if (config_.enable_tcp_reassembly) {
                comp.tcp_reasm = std::make_unique<reassembly::TcpReassembler>(
                    config_.reassembly_config
                );
            }
            if (config_.enable_ip_reassembly) {
                comp.ipv4_reasm = std::make_unique<reassembly::Ipv4Reassembler>(
                    config_.reassembly_config.ipv4_timeout
                );
                comp.ipv6_reasm = std::make_unique<reassembly::Ipv6Reassembler>(
                    config_.reassembly_config.ipv6_timeout
                );
            }

            // DNS 异常检测
            if (config_.enable_dns_anomaly_detection) {
                comp.dns_anomaly = std::make_unique<decoders::DnsAnomalyDetector>();
            }
        }

        std::cout << "  ✓ Initialized " << num_workers_ << " worker component sets\n";

        initialized_ = true;
        std::cout << "[INFO] MT detection engine initialized successfully\n";
        return true;

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Failed to initialize MT detection engine: " << e.what() << "\n";
        return false;
    }
}

void MTDetectionEngine::start() {
    if (!initialized_) {
        std::cerr << "[ERROR] Cannot start: engine not initialized\n";
        return;
    }

    if (running_) {
        std::cerr << "[WARN] Engine already running\n";
        return;
    }

    std::cout << "[INFO] Starting MT detection engine with " << num_workers_ << " workers...\n";
    running_ = true;

    // 启动工作线程
    workers_.reserve(num_workers_);
    for (size_t i = 0; i < num_workers_; ++i) {
        workers_.emplace_back([this, i]() {
            this->worker_thread(i);
        });

        // 可选：设置CPU亲和性
        if (config_.enable_cpu_affinity) {
            // Linux specific - 可以使用 pthread_setaffinity_np
            // 这里省略具体实现
        }
    }

    std::cout << "[INFO] All worker threads started\n";
}

void MTDetectionEngine::stop() {
    if (!running_) {
        return;
    }

    std::cout << "[INFO] Stopping MT detection engine...\n";
    running_ = false;

    // 等待所有工作线程完成
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    workers_.clear();
    std::cout << "[INFO] All workers stopped\n";
}

void MTDetectionEngine::process_packet(const Packet& packet) {
    // 尝试将数据包放入队列
    if (!packet_queue_.try_enqueue(packet)) {
        // 队列已满，丢弃数据包
        queue_full_drops_++;
        dropped_packets_++;
    }
}

void MTDetectionEngine::worker_thread(size_t worker_id) {
    auto& comp = worker_components_[worker_id];
    std::vector<Packet> batch;

    if (config_.enable_batching) {
        batch.reserve(config_.batch_size);
    }

    while (running_ || packet_queue_.size_approx() > 0) {
        if (config_.enable_batching) {
            // 批处理模式
            batch.clear();

            // 收集一批数据包
            Packet pkt;
            for (size_t i = 0; i < config_.batch_size; ++i) {
                if (packet_queue_.try_dequeue(pkt)) {
                    batch.push_back(std::move(pkt));
                } else {
                    break;
                }
            }

            if (!batch.empty()) {
                process_packet_batch(batch, worker_id);
            } else {
                // 队列为空，短暂休眠
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
        } else {
            // 单包处理模式
            Packet packet;
            if (packet_queue_.try_dequeue(packet)) {
                process_single_packet(packet, worker_id);
            } else {
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
        }
    }

    std::cout << "[INFO] Worker " << worker_id << " processed "
              << comp.local_stats.total_packets << " packets\n";
}

void MTDetectionEngine::process_packet_batch(std::vector<Packet>& batch, size_t worker_id) {
    for (auto& packet : batch) {
        process_single_packet(packet, worker_id);
    }
}

void MTDetectionEngine::process_single_packet(Packet& packet, size_t worker_id) {
    auto& comp = worker_components_[worker_id];

    // 更新统计
    comp.local_stats.total_packets++;
    comp.local_stats.total_bytes += packet.length();
    total_packets_++;
    total_bytes_ += packet.length();

    // 1. 协议解析 (L2-L4)
    if (!comp.eth_decoder->decode(packet)) {
        return;
    }

    auto& stack = packet.protocol_stack();

    if (stack.l3_type == ProtocolType::IPV4) {
        comp.local_stats.ipv4_packets++;
        if (!comp.ipv4_decoder->decode(packet)) {
            return;
        }
    }

    if (stack.l4_type == ProtocolType::TCP) {
        comp.local_stats.tcp_packets++;
        comp.tcp_decoder->decode(packet);
    } else if (stack.l4_type == ProtocolType::UDP) {
        comp.local_stats.udp_packets++;
        comp.udp_decoder->decode(packet);
    }

    // 2. 流跟踪
    flow::FlowKey key = extract_flow_key(packet);
    auto flow = flow_table_->get_or_create_flow(key);

    if (flow) {
        flow_manager_->update_flow(*flow, packet);
    }

    // 3. TCP/IP 重组
    if (config_.enable_tcp_reassembly && comp.tcp_reasm && stack.l4_type == ProtocolType::TCP) {
        if (flow) {
            comp.tcp_reasm->reassemble(packet, *flow);
        }
    }

    if (config_.enable_ip_reassembly) {
        if (comp.ipv4_reasm && stack.l3_type == ProtocolType::IPV4) {
            comp.ipv4_reasm->process_packet(packet);
        }
        if (comp.ipv6_reasm && stack.l3_type == ProtocolType::IPV6) {
            comp.ipv6_reasm->process_packet(packet);
        }
    }

    // 4. L7 深度解析
    const uint8_t* payload = packet.data() + stack.payload_offset;
    size_t payload_len = packet.length() - stack.payload_offset;

    // HTTP 解析
    if (comp.http_parser && stack.l4_type == ProtocolType::TCP) {
        if (key.dst_port == 80 || key.src_port == 80 ||
            key.dst_port == 8080 || key.src_port == 8080) {

            if (flow) {
                auto http_trans = comp.http_parser->parse_stream(
                    flow->flow_key(),
                    payload, payload_len,
                    key.dst_port == 80 || key.dst_port == 8080
                );
                if (http_trans) {
                    comp.local_stats.http_packets++;
                }
            }
        }
    }

    // DNS 解析和异常检测
    if (comp.dns_parser && stack.l4_type == ProtocolType::UDP) {
        if (key.dst_port == 53 || key.src_port == 53) {
            decoders::DnsMessage message;
            if (decoders::DnsParser::parse_message(payload, payload_len, message) > 0) {
                comp.local_stats.dns_packets++;

                // DNS 异常检测
                if (comp.dns_anomaly) {
                    auto anomalies = comp.dns_anomaly->detect(message);
                    if (!anomalies.empty()) {
                        comp.local_stats.anomalies_detected += anomalies.size();

                        // 输出异常（需要同步）
                        static std::mutex anomaly_mutex;
                        std::lock_guard<std::mutex> lock(anomaly_mutex);
                        for (const auto& anomaly : anomalies) {
                            std::cout << "[ANOMALY] " << anomaly.to_string() << "\n";
                        }
                    }
                }
            }
        }
    }

    // 5. 规则检测（共享 RuleManager 是线程安全的 - 只读）
    // TODO: 实现规则匹配

    // 6. 告警生成（AlertManager 需要线程安全）
    // TODO: 集成告警系统
}

void MTDetectionEngine::flush() {
    std::cout << "[INFO] Flushing MT detection engine...\n";

    // 等待队列为空
    while (packet_queue_.size_approx() > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // 导出所有活动流
    size_t exported = 0;
    flow_table_->for_each_flow([&exported](const auto& flow) {
        // TODO: 导出流数据
        (void)flow;
        exported++;
    });

    std::cout << "[INFO] Exported " << exported << " active flows\n";

    // 刷新告警
    if (alert_manager_) {
        alert_manager_->flush();
    }
}

DetectionEngineStats MTDetectionEngine::get_stats() const {
    DetectionEngineStats total_stats{};

    // 汇总所有工作线程的局部统计
    for (const auto& comp : worker_components_) {
        total_stats.ipv4_packets += comp.local_stats.ipv4_packets;
        total_stats.ipv6_packets += comp.local_stats.ipv6_packets;
        total_stats.tcp_packets += comp.local_stats.tcp_packets;
        total_stats.udp_packets += comp.local_stats.udp_packets;
        total_stats.http_packets += comp.local_stats.http_packets;
        total_stats.dns_packets += comp.local_stats.dns_packets;
        total_stats.anomalies_detected += comp.local_stats.anomalies_detected;
    }

    // 全局统计
    total_stats.total_packets = total_packets_.load();
    total_stats.total_bytes = total_bytes_.load();
    total_stats.dropped_packets = dropped_packets_.load();

    // 队列统计
    total_stats.queue_size = packet_queue_.size_approx();
    total_stats.queue_full_drops = queue_full_drops_.load();

    return total_stats;
}

flow::FlowTableStats MTDetectionEngine::get_flow_stats() const {
    if (flow_table_) {
        return flow_table_->get_stats();
    }
    return flow::FlowTableStats{};
}

size_t MTDetectionEngine::get_rule_count() const {
    if (rule_manager_) {
        return rule_manager_->size();
    }
    return 0;
}

} // namespace core
} // namespace netguardian
