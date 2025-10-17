#include "decoders/http_decoder.h"
#include "core/protocol_types.h"
#include <cstring>
#include <cctype>
#include <algorithm>

namespace netguardian {
namespace decoders {

bool HttpDecoder::can_decode(const core::Packet& packet) const {
    // HTTP 需要 TCP 传输
    if (packet.protocol_stack().l4_type != core::ProtocolType::TCP) {
        return false;
    }

    // 需要有应用层数据
    const auto& stack = packet.protocol_stack();
    return stack.payload_len > 0;
}

std::shared_ptr<DecodedData> HttpDecoder::decode(const core::Packet& packet) {
    if (!can_decode(packet)) {
        return nullptr;
    }

    const auto& stack = packet.protocol_stack();
    const char* payload = reinterpret_cast<const char*>(
        packet.data() + stack.payload_offset
    );
    size_t payload_len = stack.payload_len;

    // 检查是否以 HTTP 方法或版本开头
    if (payload_len < 8) {
        return nullptr;
    }

    auto http_data = std::make_shared<HttpData>();

    // 尝试解析请求
    if (std::strncmp(payload, "GET ", 4) == 0 ||
        std::strncmp(payload, "POST ", 5) == 0 ||
        std::strncmp(payload, "PUT ", 4) == 0 ||
        std::strncmp(payload, "DELETE ", 7) == 0 ||
        std::strncmp(payload, "HEAD ", 5) == 0 ||
        std::strncmp(payload, "OPTIONS ", 8) == 0 ||
        std::strncmp(payload, "PATCH ", 6) == 0) {

        if (parse_request(payload, payload_len, *http_data)) {
            return http_data;
        }
    }

    // 尝试解析响应
    if (std::strncmp(payload, "HTTP/", 5) == 0) {
        if (parse_response(payload, payload_len, *http_data)) {
            return http_data;
        }
    }

    return nullptr;
}

bool HttpDecoder::parse_request(const char* data, size_t len, HttpData& http_data) {
    http_data.message_type = HttpMessageType::REQUEST;

    // 查找第一行结束位置
    const char* line_end = std::strstr(data, "\r\n");
    if (!line_end || line_end - data > static_cast<ssize_t>(len)) {
        return false;
    }

    size_t line_len = line_end - data;
    std::string request_line(data, line_len);

    // 解析请求行: METHOD URI VERSION
    size_t first_space = request_line.find(' ');
    if (first_space == std::string::npos) {
        return false;
    }

    http_data.method_str = request_line.substr(0, first_space);
    http_data.method = HttpData::string_to_method(http_data.method_str);

    size_t second_space = request_line.find(' ', first_space + 1);
    if (second_space == std::string::npos) {
        return false;
    }

    http_data.uri = request_line.substr(first_space + 1, second_space - first_space - 1);
    http_data.version = request_line.substr(second_space + 1);

    // 解析头部
    parse_headers(line_end + 2, len - (line_end - data) - 2, http_data);

    return true;
}

bool HttpDecoder::parse_response(const char* data, size_t len, HttpData& http_data) {
    http_data.message_type = HttpMessageType::RESPONSE;

    // 查找第一行结束位置
    const char* line_end = std::strstr(data, "\r\n");
    if (!line_end || line_end - data > static_cast<ssize_t>(len)) {
        return false;
    }

    size_t line_len = line_end - data;
    std::string status_line(data, line_len);

    // 解析状态行: VERSION STATUS_CODE STATUS_MESSAGE
    size_t first_space = status_line.find(' ');
    if (first_space == std::string::npos) {
        return false;
    }

    http_data.version = status_line.substr(0, first_space);

    size_t second_space = status_line.find(' ', first_space + 1);
    if (second_space == std::string::npos) {
        return false;
    }

    std::string status_code_str = status_line.substr(first_space + 1, second_space - first_space - 1);
    http_data.status_code = std::atoi(status_code_str.c_str());
    http_data.status_message = status_line.substr(second_space + 1);

    // 解析头部
    parse_headers(line_end + 2, len - (line_end - data) - 2, http_data);

    return true;
}

void HttpDecoder::parse_headers(const char* data, size_t len, HttpData& http_data) {
    const char* ptr = data;
    const char* end = data + len;

    while (ptr < end) {
        // 查找行结束
        const char* line_end = std::strstr(ptr, "\r\n");
        if (!line_end || line_end > end) {
            break;
        }

        // 空行表示头部结束
        if (line_end == ptr) {
            // 头部之后是 body
            ptr = line_end + 2;
            if (ptr < end) {
                http_data.has_body = true;
                size_t body_len = std::min(static_cast<size_t>(end - ptr), size_t(1024));
                http_data.body = std::string(ptr, body_len);
            }
            break;
        }

        std::string line(ptr, line_end - ptr);

        // 解析头部字段: Name: Value
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = line.substr(0, colon);
            std::string value = line.substr(colon + 1);

            // 去除前后空格
            name.erase(0, name.find_first_not_of(" \t"));
            name.erase(name.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);

            http_data.headers[name] = value;

            // 特殊处理 Content-Length
            if (name == "Content-Length") {
                http_data.content_length = std::atoll(value.c_str());
            }
        }

        ptr = line_end + 2;
    }
}

} // namespace decoders
} // namespace netguardian
