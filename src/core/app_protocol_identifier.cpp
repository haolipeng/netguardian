#include "core/app_protocol_identifier.h"
#include <arpa/inet.h>
#include <cstring>
#include <algorithm>
#include <cctype>

namespace netguardian {
namespace core {

AppProtocolIdentifier::AppProtocolIdentifier()
    : use_port_based_(true)
    , use_dpi_(true)
    , use_heuristic_(false)  // Disabled by default (performance)
{
    load_builtin_signatures();
}

AppProtocolIdentifier::~AppProtocolIdentifier() {
}

IdentificationResult AppProtocolIdentifier::identify(const Packet& packet) {
    const ProtocolStack& stack = packet.protocol_stack();
    
    // Need at least L4 info
    if (stack.l4_type == ProtocolType::UNKNOWN) {
        return IdentificationResult();
    }

    // Get transport type
    TransportType transport = TransportType::NONE;
    if (stack.l4_type == ProtocolType::TCP) {
        transport = TransportType::TCP;
    } else if (stack.l4_type == ProtocolType::UDP) {
        transport = TransportType::UDP;
    }

    // Extract ports
    uint16_t src_port = 0, dst_port = 0;
    if (stack.l4_offset > 0 && static_cast<size_t>(stack.l4_offset) + 4 <= packet.length()) {
        const uint8_t* l4_data = packet.data() + stack.l4_offset;
        src_port = ntohs(*reinterpret_cast<const uint16_t*>(l4_data));
        dst_port = ntohs(*reinterpret_cast<const uint16_t*>(l4_data + 2));
    }

    // Get payload
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    if (stack.payload_offset > 0 && static_cast<size_t>(stack.payload_offset) < packet.length()) {
        payload = packet.data() + stack.payload_offset;
        payload_len = packet.length() - stack.payload_offset;
    }

    IdentificationResult result;
    
    // Try DPI first (most accurate)
    if (use_dpi_ && payload && payload_len > 0) {
        result = identify_by_dpi(payload, payload_len, transport);
        if (result.confidence >= 80) {
            return result;  // High confidence, return immediately
        }
    }

    // Try port-based (fast fallback)
    if (use_port_based_) {
        IdentificationResult port_result = identify_by_port(src_port, dst_port, transport);
        if (port_result.confidence > result.confidence) {
            result = port_result;
        }
    }

    // Try heuristic if enabled
    if (use_heuristic_ && result.confidence < 70) {
        IdentificationResult heuristic_result = identify_by_heuristic(packet);
        if (heuristic_result.confidence > result.confidence) {
            result = heuristic_result;
        }
    }

    return result;
}

IdentificationResult AppProtocolIdentifier::identify_by_port(uint16_t src_port, uint16_t dst_port, TransportType transport) {
    IdentificationResult result;
    result.method = "port";
    result.confidence = 50;  // Port-based is only 50% confident

    for (const auto& sig : signatures_) {
        // Check transport layer match
        if (sig.required_transport != TransportType::NONE && 
            sig.required_transport != transport) {
            continue;
        }

        // Check server ports (destination port usually)
        for (uint16_t port : sig.server_ports) {
            if (port == dst_port || port == src_port) {
                result.protocol = sig.protocol;
                result.details = "Matched port " + std::to_string(port);
                return result;
            }
        }
    }

    return result;
}

IdentificationResult AppProtocolIdentifier::identify_by_dpi(const uint8_t* payload, size_t payload_len, TransportType transport) {
    IdentificationResult result;
    result.method = "dpi";

    for (const auto& sig : signatures_) {
        // Check transport requirement
        if (sig.required_transport != TransportType::NONE && 
            sig.required_transport != transport) {
            continue;
        }

        int matches = 0;
        int total_checks = 0;

        // Check byte patterns
        for (const auto& pattern : sig.patterns) {
            total_checks++;
            if (match_pattern(payload, payload_len, pattern)) {
                matches++;
            }
        }

        // Check keywords
        if (!sig.keywords.empty()) {
            total_checks++;
            if (match_keywords(payload, payload_len, sig.keywords)) {
                matches++;
            }
        }

        // Calculate confidence
        if (total_checks > 0) {
            int confidence = (matches * 100) / total_checks;
            if (confidence > result.confidence) {
                result.protocol = sig.protocol;
                result.confidence = confidence;
                result.details = "Matched " + std::to_string(matches) + "/" + 
                                std::to_string(total_checks) + " signatures";
            }
        }
    }

    return result;
}

IdentificationResult AppProtocolIdentifier::identify_by_heuristic(const Packet& packet) {
    // TODO: Implement statistical/behavioral analysis
    // - Packet size distribution
    // - Inter-arrival times
    // - Flow patterns
    // - Entropy analysis
    
    IdentificationResult result;
    result.method = "heuristic";
    result.confidence = 0;
    return result;
}

bool AppProtocolIdentifier::match_pattern(const uint8_t* payload, size_t len, 
                                         const ProtocolSignature::Pattern& pattern) {
    if (pattern.offset + pattern.bytes.size() > len) {
        return false;
    }

    const uint8_t* start = payload + pattern.offset;
    
    if (pattern.case_sensitive) {
        return std::memcmp(start, pattern.bytes.data(), pattern.bytes.size()) == 0;
    } else {
        // Case-insensitive comparison
        for (size_t i = 0; i < pattern.bytes.size(); ++i) {
            if (std::tolower(start[i]) != std::tolower(pattern.bytes[i])) {
                return false;
            }
        }
        return true;
    }
}

bool AppProtocolIdentifier::match_keywords(const uint8_t* payload, size_t len, 
                                          const std::vector<std::string>& keywords) {
    std::string text = extract_printable(payload, len, 200);
    
    for (const auto& keyword : keywords) {
        if (text.find(keyword) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

std::string AppProtocolIdentifier::extract_printable(const uint8_t* data, size_t len, size_t max_len) {
    std::string result;
    result.reserve(std::min(len, max_len));
    
    for (size_t i = 0; i < len && i < max_len; ++i) {
        if (std::isprint(data[i]) || data[i] == '\n' || data[i] == '\r') {
            result += static_cast<char>(data[i]);
        }
    }
    
    return result;
}

void AppProtocolIdentifier::register_signature(const ProtocolSignature& signature) {
    signatures_.push_back(signature);
}

void AppProtocolIdentifier::load_builtin_signatures() {
    // HTTP Signature
    {
        ProtocolSignature sig;
        sig.protocol = ProtocolType::HTTP;
        sig.name = "HTTP";
        sig.server_ports = {80, 8080, 8000, 8888};
        sig.required_transport = TransportType::TCP;
        sig.keywords = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "HTTP/1.", "HTTP/2"};
        sig.confidence = 90;
        signatures_.push_back(sig);
    }

    // HTTPS/TLS Signature
    {
        ProtocolSignature sig;
        sig.protocol = ProtocolType::HTTPS;
        sig.name = "HTTPS/TLS";
        sig.server_ports = {443, 8443};
        sig.required_transport = TransportType::TCP;
        
        // TLS handshake starts with 0x16 0x03 (Content Type: Handshake, Version: SSL 3.x/TLS 1.x)
        ProtocolSignature::Pattern tls_pattern;
        tls_pattern.bytes = {0x16, 0x03};
        tls_pattern.offset = 0;
        tls_pattern.case_sensitive = true;
        sig.patterns.push_back(tls_pattern);
        
        sig.confidence = 95;
        signatures_.push_back(sig);
    }

    // DNS Signature
    {
        ProtocolSignature sig;
        sig.protocol = ProtocolType::DNS;
        sig.name = "DNS";
        sig.server_ports = {53};
        sig.required_transport = TransportType::UDP;  // Also TCP, but UDP is more common
        sig.confidence = 85;
        signatures_.push_back(sig);
    }

    // SSH Signature
    {
        ProtocolSignature sig;
        sig.protocol = ProtocolType::SSH;
        sig.name = "SSH";
        sig.server_ports = {22};
        sig.required_transport = TransportType::TCP;
        sig.keywords = {"SSH-"};
        sig.confidence = 95;
        signatures_.push_back(sig);
    }

    // FTP Signature
    {
        ProtocolSignature sig;
        sig.protocol = ProtocolType::FTP;
        sig.name = "FTP";
        sig.server_ports = {21};
        sig.required_transport = TransportType::TCP;
        sig.keywords = {"220 ", "USER ", "PASS ", "RETR ", "STOR "};
        sig.confidence = 90;
        signatures_.push_back(sig);
    }

    // SMTP Signature
    {
        ProtocolSignature sig;
        sig.protocol = ProtocolType::SMTP;
        sig.name = "SMTP";
        sig.server_ports = {25, 587};
        sig.required_transport = TransportType::TCP;
        sig.keywords = {"220 ", "HELO ", "EHLO ", "MAIL FROM:", "RCPT TO:"};
        sig.confidence = 90;
        signatures_.push_back(sig);
    }

    // MySQL Signature
    {
        ProtocolSignature sig;
        sig.protocol = ProtocolType::MYSQL;
        sig.name = "MySQL";
        sig.server_ports = {3306};
        sig.required_transport = TransportType::TCP;
        sig.confidence = 80;
        signatures_.push_back(sig);
    }

    // RDP Signature
    {
        ProtocolSignature sig;
        sig.protocol = ProtocolType::RDP;
        sig.name = "RDP";
        sig.server_ports = {3389};
        sig.required_transport = TransportType::TCP;
        sig.confidence = 85;
        signatures_.push_back(sig);
    }
}

} // namespace core
} // namespace netguardian
