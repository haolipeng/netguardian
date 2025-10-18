#ifndef NETGUARDIAN_DECODERS_HTTP_PARSER_H
#define NETGUARDIAN_DECODERS_HTTP_PARSER_H

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <cstdint>

namespace netguardian {
namespace decoders {

// HTTP 方法
enum class HttpMethod {
    UNKNOWN,
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    TRACE,
    CONNECT,
    PATCH
};

// HTTP 版本
enum class HttpVersion {
    UNKNOWN,
    HTTP_0_9,
    HTTP_1_0,
    HTTP_1_1,
    HTTP_2_0,
    HTTP_3_0
};

// HTTP 消息类型
enum class HttpMessageType {
    UNKNOWN,
    REQUEST,
    RESPONSE
};

// HTTP 头部
using HttpHeaders = std::map<std::string, std::string>;

// HTTP 请求
struct HttpRequest {
    HttpMethod method;          // 请求方法
    std::string uri;            // 请求URI
    std::string path;           // 路径部分
    std::string query;          // 查询字符串
    HttpVersion version;        // HTTP版本
    HttpHeaders headers;        // 请求头
    std::vector<uint8_t> body;  // 请求体

    // 常用头部快速访问
    std::string host;           // Host头
    std::string user_agent;     // User-Agent头
    std::string referer;        // Referer头
    std::string content_type;   // Content-Type头
    size_t content_length;      // Content-Length

    HttpRequest()
        : method(HttpMethod::UNKNOWN)
        , version(HttpVersion::UNKNOWN)
        , content_length(0)
    {}

    // 获取方法字符串
    std::string method_string() const;

    // 获取版本字符串
    std::string version_string() const;

    // 是否有Body
    bool has_body() const { return !body.empty(); }
};

// HTTP 响应
struct HttpResponse {
    HttpVersion version;        // HTTP版本
    uint16_t status_code;       // 状态码
    std::string reason_phrase;  // 状态描述
    HttpHeaders headers;        // 响应头
    std::vector<uint8_t> body;  // 响应体

    // 常用头部快速访问
    std::string content_type;   // Content-Type头
    size_t content_length;      // Content-Length
    std::string server;         // Server头
    std::string location;       // Location头（重定向）

    HttpResponse()
        : version(HttpVersion::UNKNOWN)
        , status_code(0)
        , content_length(0)
    {}

    // 获取版本字符串
    std::string version_string() const;

    // 是否有Body
    bool has_body() const { return !body.empty(); }

    // 是否成功（2xx）
    bool is_success() const { return status_code >= 200 && status_code < 300; }

    // 是否重定向（3xx）
    bool is_redirect() const { return status_code >= 300 && status_code < 400; }

    // 是否客户端错误（4xx）
    bool is_client_error() const { return status_code >= 400 && status_code < 500; }

    // 是否服务器错误（5xx）
    bool is_server_error() const { return status_code >= 500 && status_code < 600; }
};

// HTTP 解析器
class HttpParser {
public:
    HttpParser() = default;

    // 解析HTTP请求
    // 返回：成功解析的字节数，0表示需要更多数据，-1表示解析错误
    static int parse_request(const uint8_t* data, size_t len, HttpRequest& request);

    // 解析HTTP响应
    static int parse_response(const uint8_t* data, size_t len, HttpResponse& response);

    // 辅助函数：字符串转HTTP方法
    static HttpMethod string_to_method(const std::string& str);

    // 辅助函数：HTTP方法转字符串
    static std::string method_to_string(HttpMethod method);

    // 辅助函数：字符串转HTTP版本
    static HttpVersion string_to_version(const std::string& str);

    // 辅助函数：HTTP版本转字符串
    static std::string version_to_string(HttpVersion version);

    // 辅助函数：解析URI（分离path和query）
    static void parse_uri(const std::string& uri, std::string& path, std::string& query);

private:
    // 解析请求行（GET / HTTP/1.1）
    static bool parse_request_line(const std::string& line, HttpRequest& request);

    // 解析状态行（HTTP/1.1 200 OK）
    static bool parse_status_line(const std::string& line, HttpResponse& response);

    // 解析头部
    static bool parse_headers(const std::vector<std::string>& lines, HttpHeaders& headers);

    // 提取常用头部
    static void extract_common_headers(const HttpHeaders& headers, HttpRequest& request);
    static void extract_common_headers(const HttpHeaders& headers, HttpResponse& response);

    // 分割行
    static std::vector<std::string> split_lines(const uint8_t* data, size_t len);

    // 查找\r\n\r\n（头部结束标记）
    static int find_header_end(const uint8_t* data, size_t len);

    // 辅助：trim字符串
    static std::string trim(const std::string& str);

    // 辅助：转小写
    static std::string to_lower(const std::string& str);
};

} // namespace decoders
} // namespace netguardian

#endif // NETGUARDIAN_DECODERS_HTTP_PARSER_H
