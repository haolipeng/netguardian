#include "decoders/http_parser.h"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstring>

namespace netguardian {
namespace decoders {

// ============================================================================
// HttpRequest 方法实现
// ============================================================================

std::string HttpRequest::method_string() const {
    return HttpParser::method_to_string(method);
}

std::string HttpRequest::version_string() const {
    return HttpParser::version_to_string(version);
}

// ============================================================================
// HttpResponse 方法实现
// ============================================================================

std::string HttpResponse::version_string() const {
    return HttpParser::version_to_string(version);
}

// ============================================================================
// HttpParser 方法实现
// ============================================================================

int HttpParser::parse_request(const uint8_t* data, size_t len, HttpRequest& request) {
    if (!data || len == 0) {
        return -1;
    }

    // 查找头部结束位置
    int header_end = find_header_end(data, len);
    if (header_end < 0) {
        return 0;  // 需要更多数据
    }

    // 分割行
    auto lines = split_lines(data, header_end);
    if (lines.empty()) {
        return -1;
    }

    // 解析请求行
    if (!parse_request_line(lines[0], request)) {
        return -1;
    }

    // 解析头部
    std::vector<std::string> header_lines(lines.begin() + 1, lines.end());
    if (!parse_headers(header_lines, request.headers)) {
        return -1;
    }

    // 提取常用头部
    extract_common_headers(request.headers, request);

    // 解析Body（如果有）
    size_t total_header_len = header_end + 4;  // +4 for \r\n\r\n
    if (request.content_length > 0 && len >= total_header_len + request.content_length) {
        request.body.assign(data + total_header_len,
                           data + total_header_len + request.content_length);
        return total_header_len + request.content_length;
    }

    return total_header_len;
}

int HttpParser::parse_response(const uint8_t* data, size_t len, HttpResponse& response) {
    if (!data || len == 0) {
        return -1;
    }

    // 查找头部结束位置
    int header_end = find_header_end(data, len);
    if (header_end < 0) {
        return 0;  // 需要更多数据
    }

    // 分割行
    auto lines = split_lines(data, header_end);
    if (lines.empty()) {
        return -1;
    }

    // 解析状态行
    if (!parse_status_line(lines[0], response)) {
        return -1;
    }

    // 解析头部
    std::vector<std::string> header_lines(lines.begin() + 1, lines.end());
    if (!parse_headers(header_lines, response.headers)) {
        return -1;
    }

    // 提取常用头部
    extract_common_headers(response.headers, response);

    // 解析Body（如果有）
    size_t total_header_len = header_end + 4;  // +4 for \r\n\r\n
    if (response.content_length > 0 && len >= total_header_len + response.content_length) {
        response.body.assign(data + total_header_len,
                            data + total_header_len + response.content_length);
        return total_header_len + response.content_length;
    }

    return total_header_len;
}

// ============================================================================
// 辅助函数
// ============================================================================

HttpMethod HttpParser::string_to_method(const std::string& str) {
    if (str == "GET") return HttpMethod::GET;
    if (str == "POST") return HttpMethod::POST;
    if (str == "PUT") return HttpMethod::PUT;
    if (str == "DELETE") return HttpMethod::DELETE;
    if (str == "HEAD") return HttpMethod::HEAD;
    if (str == "OPTIONS") return HttpMethod::OPTIONS;
    if (str == "TRACE") return HttpMethod::TRACE;
    if (str == "CONNECT") return HttpMethod::CONNECT;
    if (str == "PATCH") return HttpMethod::PATCH;
    return HttpMethod::UNKNOWN;
}

std::string HttpParser::method_to_string(HttpMethod method) {
    switch (method) {
        case HttpMethod::GET: return "GET";
        case HttpMethod::POST: return "POST";
        case HttpMethod::PUT: return "PUT";
        case HttpMethod::DELETE: return "DELETE";
        case HttpMethod::HEAD: return "HEAD";
        case HttpMethod::OPTIONS: return "OPTIONS";
        case HttpMethod::TRACE: return "TRACE";
        case HttpMethod::CONNECT: return "CONNECT";
        case HttpMethod::PATCH: return "PATCH";
        default: return "UNKNOWN";
    }
}

HttpVersion HttpParser::string_to_version(const std::string& str) {
    if (str == "HTTP/0.9") return HttpVersion::HTTP_0_9;
    if (str == "HTTP/1.0") return HttpVersion::HTTP_1_0;
    if (str == "HTTP/1.1") return HttpVersion::HTTP_1_1;
    if (str == "HTTP/2.0" || str == "HTTP/2") return HttpVersion::HTTP_2_0;
    if (str == "HTTP/3.0" || str == "HTTP/3") return HttpVersion::HTTP_3_0;
    return HttpVersion::UNKNOWN;
}

std::string HttpParser::version_to_string(HttpVersion version) {
    switch (version) {
        case HttpVersion::HTTP_0_9: return "HTTP/0.9";
        case HttpVersion::HTTP_1_0: return "HTTP/1.0";
        case HttpVersion::HTTP_1_1: return "HTTP/1.1";
        case HttpVersion::HTTP_2_0: return "HTTP/2.0";
        case HttpVersion::HTTP_3_0: return "HTTP/3.0";
        default: return "UNKNOWN";
    }
}

void HttpParser::parse_uri(const std::string& uri, std::string& path, std::string& query) {
    size_t pos = uri.find('?');
    if (pos != std::string::npos) {
        path = uri.substr(0, pos);
        query = uri.substr(pos + 1);
    } else {
        path = uri;
        query.clear();
    }
}

// ============================================================================
// 私有辅助函数
// ============================================================================

bool HttpParser::parse_request_line(const std::string& line, HttpRequest& request) {
    // 格式: METHOD URI HTTP/VERSION
    std::istringstream iss(line);
    std::string method_str, uri_str, version_str;

    if (!(iss >> method_str >> uri_str >> version_str)) {
        return false;
    }

    request.method = string_to_method(method_str);
    request.uri = uri_str;
    parse_uri(uri_str, request.path, request.query);
    request.version = string_to_version(version_str);

    return request.method != HttpMethod::UNKNOWN &&
           request.version != HttpVersion::UNKNOWN;
}

bool HttpParser::parse_status_line(const std::string& line, HttpResponse& response) {
    // 格式: HTTP/VERSION CODE REASON
    std::istringstream iss(line);
    std::string version_str, code_str;

    if (!(iss >> version_str >> code_str)) {
        return false;
    }

    response.version = string_to_version(version_str);

    try {
        response.status_code = std::stoi(code_str);
    } catch (...) {
        return false;
    }

    // 读取剩余部分作为reason phrase
    std::getline(iss, response.reason_phrase);
    response.reason_phrase = trim(response.reason_phrase);

    return response.version != HttpVersion::UNKNOWN &&
           response.status_code >= 100 && response.status_code < 600;
}

bool HttpParser::parse_headers(const std::vector<std::string>& lines, HttpHeaders& headers) {
    for (const auto& line : lines) {
        if (line.empty()) {
            continue;
        }

        size_t pos = line.find(':');
        if (pos == std::string::npos) {
            continue;  // 跳过无效行
        }

        std::string name = trim(line.substr(0, pos));
        std::string value = trim(line.substr(pos + 1));

        // Header名转小写（HTTP header名不区分大小写）
        headers[to_lower(name)] = value;
    }

    return true;
}

void HttpParser::extract_common_headers(const HttpHeaders& headers, HttpRequest& request) {
    auto it = headers.find("host");
    if (it != headers.end()) {
        request.host = it->second;
    }

    it = headers.find("user-agent");
    if (it != headers.end()) {
        request.user_agent = it->second;
    }

    it = headers.find("referer");
    if (it != headers.end()) {
        request.referer = it->second;
    }

    it = headers.find("content-type");
    if (it != headers.end()) {
        request.content_type = it->second;
    }

    it = headers.find("content-length");
    if (it != headers.end()) {
        try {
            request.content_length = std::stoull(it->second);
        } catch (...) {
            request.content_length = 0;
        }
    }
}

void HttpParser::extract_common_headers(const HttpHeaders& headers, HttpResponse& response) {
    auto it = headers.find("content-type");
    if (it != headers.end()) {
        response.content_type = it->second;
    }

    it = headers.find("content-length");
    if (it != headers.end()) {
        try {
            response.content_length = std::stoull(it->second);
        } catch (...) {
            response.content_length = 0;
        }
    }

    it = headers.find("server");
    if (it != headers.end()) {
        response.server = it->second;
    }

    it = headers.find("location");
    if (it != headers.end()) {
        response.location = it->second;
    }
}

std::vector<std::string> HttpParser::split_lines(const uint8_t* data, size_t len) {
    std::vector<std::string> lines;
    std::string line;

    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\r' && i + 1 < len && data[i + 1] == '\n') {
            if (!line.empty()) {
                lines.push_back(line);
                line.clear();
            }
            i++;  // 跳过\n
        } else if (data[i] == '\n') {
            if (!line.empty()) {
                lines.push_back(line);
                line.clear();
            }
        } else {
            line += static_cast<char>(data[i]);
        }
    }

    if (!line.empty()) {
        lines.push_back(line);
    }

    return lines;
}

int HttpParser::find_header_end(const uint8_t* data, size_t len) {
    // 查找\r\n\r\n
    for (size_t i = 0; i + 3 < len; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n' &&
            data[i + 2] == '\r' && data[i + 3] == '\n') {
            return i;
        }
    }

    // 查找\n\n（不太标准但有些服务器会用）
    for (size_t i = 0; i + 1 < len; i++) {
        if (data[i] == '\n' && data[i + 1] == '\n') {
            return i;
        }
    }

    return -1;  // 未找到
}

std::string HttpParser::trim(const std::string& str) {
    size_t start = 0;
    size_t end = str.length();

    while (start < end && std::isspace(static_cast<unsigned char>(str[start]))) {
        start++;
    }

    while (end > start && std::isspace(static_cast<unsigned char>(str[end - 1]))) {
        end--;
    }

    return str.substr(start, end - start);
}

std::string HttpParser::to_lower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

} // namespace decoders
} // namespace netguardian
