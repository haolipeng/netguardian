#ifndef NETGUARDIAN_CORE_APP_PROTOCOL_IDENTIFIER_H
#define NETGUARDIAN_CORE_APP_PROTOCOL_IDENTIFIER_H

#include "core/packet.h"
#include "core/protocol_types.h"
#include <vector>
#include <string>
#include <functional>

namespace netguardian {
namespace core {

/**
 * Application Protocol Signature
 * Defines characteristics used to identify a protocol
 */
struct ProtocolSignature {
    ProtocolType protocol;
    std::string name;
    
    // Port-based identification
    std::vector<uint16_t> server_ports;
    std::vector<uint16_t> client_ports;
    
    // Payload pattern matching
    struct Pattern {
        std::vector<uint8_t> bytes;     // Byte sequence to match
        size_t offset;                   // Offset in payload (0 = start)
        bool case_sensitive;
        
        Pattern() : offset(0), case_sensitive(true) {}
    };
    std::vector<Pattern> patterns;
    
    // String-based signatures (for text protocols)
    std::vector<std::string> keywords;  // e.g., "GET ", "POST ", "HTTP/"
    
    // Transport layer requirement
    TransportType required_transport;   // TCP, UDP, or NONE (any)
    
    // Confidence threshold (0-100)
    int confidence;
    
    ProtocolSignature()
        : protocol(ProtocolType::UNKNOWN)
        , required_transport(TransportType::NONE)
        , confidence(0)
    {}
};

/**
 * Identification Result
 */
struct IdentificationResult {
    ProtocolType protocol;
    int confidence;           // 0-100
    std::string method;       // "port", "dpi", "heuristic", "ml"
    std::string details;      // Additional information
    
    IdentificationResult()
        : protocol(ProtocolType::UNKNOWN)
        , confidence(0)
        , method("unknown")
    {}
};

/**
 * Application Protocol Identifier
 * 
 * Uses multiple techniques for accurate L7 protocol identification:
 * 1. Port-based (fast, low accuracy)
 * 2. Deep Packet Inspection - DPI (accurate, moderate cost)
 * 3. Statistical/Behavioral analysis (high accuracy, high cost)
 * 4. Machine Learning (future enhancement)
 */
class AppProtocolIdentifier {
public:
    AppProtocolIdentifier();
    ~AppProtocolIdentifier();

    /**
     * Identify application protocol in a packet
     * @param packet Packet with parsed L2-L4 headers
     * @return Identification result with confidence
     */
    IdentificationResult identify(const Packet& packet);

    /**
     * Register custom protocol signature
     * @param signature Protocol signature definition
     */
    void register_signature(const ProtocolSignature& signature);

    /**
     * Enable/disable identification methods
     */
    void enable_port_based(bool enable) { use_port_based_ = enable; }
    void enable_dpi(bool enable) { use_dpi_ = enable; }
    void enable_heuristic(bool enable) { use_heuristic_ = enable; }

private:
    /**
     * Method 1: Port-based identification
     * Fast but can be misleading due to dynamic ports
     */
    IdentificationResult identify_by_port(uint16_t src_port, uint16_t dst_port, TransportType transport);

    /**
     * Method 2: Deep Packet Inspection
     * Examines payload for protocol-specific patterns
     */
    IdentificationResult identify_by_dpi(const uint8_t* payload, size_t payload_len, TransportType transport);

    /**
     * Method 3: Heuristic analysis
     * Uses statistical features and behavioral patterns
     */
    IdentificationResult identify_by_heuristic(const Packet& packet);

    /**
     * Check if payload matches a signature pattern
     */
    bool match_pattern(const uint8_t* payload, size_t len, const ProtocolSignature::Pattern& pattern);

    /**
     * Check if payload contains keywords
     */
    bool match_keywords(const uint8_t* payload, size_t len, const std::vector<std::string>& keywords);

    /**
     * Load built-in protocol signatures
     */
    void load_builtin_signatures();

    /**
     * Extract printable string from payload (for text protocols)
     */
    std::string extract_printable(const uint8_t* data, size_t len, size_t max_len = 100);

private:
    std::vector<ProtocolSignature> signatures_;
    bool use_port_based_;
    bool use_dpi_;
    bool use_heuristic_;
};

} // namespace core
} // namespace netguardian

#endif // NETGUARDIAN_CORE_APP_PROTOCOL_IDENTIFIER_H
