#include "core/protocol_types.h"

namespace netguardian {
namespace core {

const char* protocol_type_to_string(ProtocolType type) {
    switch (type) {
        case ProtocolType::UNKNOWN: return "UNKNOWN";
        case ProtocolType::ETHERNET: return "ETHERNET";
        case ProtocolType::IPV4: return "IPv4";
        case ProtocolType::IPV6: return "IPv6";
        case ProtocolType::ARP: return "ARP";
        case ProtocolType::ICMP: return "ICMP";
        case ProtocolType::IGMP: return "IGMP";
        case ProtocolType::TCP: return "TCP";
        case ProtocolType::UDP: return "UDP";
        case ProtocolType::IPV6_ICMP: return "ICMPv6";
        case ProtocolType::SCTP: return "SCTP";
        case ProtocolType::FTP: return "FTP";
        case ProtocolType::SSH: return "SSH";
        case ProtocolType::TELNET: return "TELNET";
        case ProtocolType::SMTP: return "SMTP";
        case ProtocolType::DNS: return "DNS";
        case ProtocolType::HTTP: return "HTTP";
        case ProtocolType::POP3: return "POP3";
        case ProtocolType::IMAP: return "IMAP";
        case ProtocolType::HTTPS: return "HTTPS";
        case ProtocolType::SMB: return "SMB";
        case ProtocolType::MYSQL: return "MYSQL";
        case ProtocolType::RDP: return "RDP";
        default: return "UNKNOWN";
    }
}

const char* port_to_protocol_name(uint16_t port) {
    switch (port) {
        case WellKnownPort::FTP: return "FTP";
        case WellKnownPort::SSH: return "SSH";
        case WellKnownPort::TELNET: return "TELNET";
        case WellKnownPort::SMTP: return "SMTP";
        case WellKnownPort::DNS: return "DNS";
        case WellKnownPort::HTTP: return "HTTP";
        case WellKnownPort::POP3: return "POP3";
        case WellKnownPort::IMAP: return "IMAP";
        case WellKnownPort::HTTPS: return "HTTPS";
        case WellKnownPort::SMB: return "SMB";
        case WellKnownPort::MYSQL: return "MYSQL";
        case WellKnownPort::RDP: return "RDP";
        default: return "UNKNOWN";
    }
}

} // namespace core
} // namespace netguardian
