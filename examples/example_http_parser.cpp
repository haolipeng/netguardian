/*
 * HTTP Parser Example
 *
 * 演示 HTTP 深度解析功能：
 * 1. HTTP 请求解析（GET/POST）
 * 2. HTTP 响应解析
 * 3. 头部提取
 * 4. Body 提取
 * 5. 常用字段访问
 */

#include "decoders/http_parser.h"
#include <iostream>
#include <iomanip>
#include <cstring>

using namespace netguardian::decoders;

// 打印分隔线
void print_separator() {
    std::cout << std::string(60, '=') << std::endl;
}

// 打印HTTP请求
void print_request(const HttpRequest& req) {
    std::cout << "\n=== HTTP Request ===" << std::endl;
    std::cout << "Method:  " << req.method_string() << std::endl;
    std::cout << "URI:     " << req.uri << std::endl;
    std::cout << "Path:    " << req.path << std::endl;
    if (!req.query.empty()) {
        std::cout << "Query:   " << req.query << std::endl;
    }
    std::cout << "Version: " << req.version_string() << std::endl;

    std::cout << "\n--- Common Headers ---" << std::endl;
    if (!req.host.empty()) {
        std::cout << "Host:         " << req.host << std::endl;
    }
    if (!req.user_agent.empty()) {
        std::cout << "User-Agent:   " << req.user_agent << std::endl;
    }
    if (!req.referer.empty()) {
        std::cout << "Referer:      " << req.referer << std::endl;
    }
    if (!req.content_type.empty()) {
        std::cout << "Content-Type: " << req.content_type << std::endl;
    }
    if (req.content_length > 0) {
        std::cout << "Content-Length: " << req.content_length << std::endl;
    }

    if (!req.headers.empty()) {
        std::cout << "\n--- All Headers (" << req.headers.size() << ") ---" << std::endl;
        for (const auto& header : req.headers) {
            std::cout << "  " << header.first << ": " << header.second << std::endl;
        }
    }

    if (req.has_body()) {
        std::cout << "\n--- Body (" << req.body.size() << " bytes) ---" << std::endl;
        std::string body_str(req.body.begin(), req.body.end());
        std::cout << body_str << std::endl;
    }
}

// 打印HTTP响应
void print_response(const HttpResponse& resp) {
    std::cout << "\n=== HTTP Response ===" << std::endl;
    std::cout << "Version:     " << resp.version_string() << std::endl;
    std::cout << "Status Code: " << resp.status_code << std::endl;
    std::cout << "Reason:      " << resp.reason_phrase << std::endl;

    std::cout << "\n--- Status Category ---" << std::endl;
    if (resp.is_success()) {
        std::cout << "Success (2xx)" << std::endl;
    } else if (resp.is_redirect()) {
        std::cout << "Redirect (3xx)" << std::endl;
    } else if (resp.is_client_error()) {
        std::cout << "Client Error (4xx)" << std::endl;
    } else if (resp.is_server_error()) {
        std::cout << "Server Error (5xx)" << std::endl;
    }

    std::cout << "\n--- Common Headers ---" << std::endl;
    if (!resp.server.empty()) {
        std::cout << "Server:        " << resp.server << std::endl;
    }
    if (!resp.content_type.empty()) {
        std::cout << "Content-Type:  " << resp.content_type << std::endl;
    }
    if (resp.content_length > 0) {
        std::cout << "Content-Length: " << resp.content_length << std::endl;
    }
    if (!resp.location.empty()) {
        std::cout << "Location:      " << resp.location << std::endl;
    }

    if (!resp.headers.empty()) {
        std::cout << "\n--- All Headers (" << resp.headers.size() << ") ---" << std::endl;
        for (const auto& header : resp.headers) {
            std::cout << "  " << header.first << ": " << header.second << std::endl;
        }
    }

    if (resp.has_body()) {
        std::cout << "\n--- Body (" << resp.body.size() << " bytes) ---" << std::endl;
        std::string body_str(resp.body.begin(), resp.body.end());
        std::cout << body_str.substr(0, 200);  // 只显示前200字节
        if (body_str.size() > 200) {
            std::cout << "... (truncated)";
        }
        std::cout << std::endl;
    }
}

// 测试 1：简单GET请求
void test_simple_get_request() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 1: Simple GET Request                          ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝" << std::endl;

    std::string http_data =
        "GET /index.html HTTP/1.1\r\n"
        "Host: www.example.com\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept: text/html\r\n"
        "\r\n";

    HttpRequest request;
    int parsed = HttpParser::parse_request(
        reinterpret_cast<const uint8_t*>(http_data.data()),
        http_data.size(),
        request
    );

    std::cout << "Parsed bytes: " << parsed << " / " << http_data.size() << std::endl;
    print_request(request);
}

// 测试 2：带查询字符串的GET请求
void test_get_with_query() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 2: GET Request with Query String               ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝" << std::endl;

    std::string http_data =
        "GET /search?q=network+security&lang=en HTTP/1.1\r\n"
        "Host: search.example.com\r\n"
        "User-Agent: NetGuardian/1.0\r\n"
        "Accept: application/json\r\n"
        "Referer: https://www.example.com/\r\n"
        "\r\n";

    HttpRequest request;
    int parsed = HttpParser::parse_request(
        reinterpret_cast<const uint8_t*>(http_data.data()),
        http_data.size(),
        request
    );

    std::cout << "Parsed bytes: " << parsed << std::endl;
    print_request(request);
}

// 测试 3：POST请求带Body
void test_post_with_body() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 3: POST Request with Body                      ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝" << std::endl;

    std::string body = "username=admin&password=secret123";
    std::string http_data =
        "POST /api/login HTTP/1.1\r\n"
        "Host: api.example.com\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "User-Agent: NetGuardian/1.0\r\n"
        "\r\n" +
        body;

    HttpRequest request;
    int parsed = HttpParser::parse_request(
        reinterpret_cast<const uint8_t*>(http_data.data()),
        http_data.size(),
        request
    );

    std::cout << "Parsed bytes: " << parsed << " / " << http_data.size() << std::endl;
    print_request(request);
}

// 测试 4：200 OK响应
void test_200_response() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 4: HTTP 200 OK Response                        ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝" << std::endl;

    std::string body = "<html><body><h1>Hello, World!</h1></body></html>";
    std::string http_data =
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx/1.18.0\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Connection: keep-alive\r\n"
        "\r\n" +
        body;

    HttpResponse response;
    int parsed = HttpParser::parse_response(
        reinterpret_cast<const uint8_t*>(http_data.data()),
        http_data.size(),
        response
    );

    std::cout << "Parsed bytes: " << parsed << " / " << http_data.size() << std::endl;
    print_response(response);
}

// 测试 5：404 Not Found响应
void test_404_response() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 5: HTTP 404 Not Found Response                 ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝" << std::endl;

    std::string body = "{\"error\":\"Resource not found\"}";
    std::string http_data =
        "HTTP/1.1 404 Not Found\r\n"
        "Server: Apache/2.4.41\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "\r\n" +
        body;

    HttpResponse response;
    int parsed = HttpParser::parse_response(
        reinterpret_cast<const uint8_t*>(http_data.data()),
        http_data.size(),
        response
    );

    std::cout << "Parsed bytes: " << parsed << std::endl;
    print_response(response);
}

// 测试 6：302重定向响应
void test_302_redirect() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Test 6: HTTP 302 Redirect Response                  ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝" << std::endl;

    std::string http_data =
        "HTTP/1.1 302 Found\r\n"
        "Server: nginx\r\n"
        "Location: https://www.example.com/new-location\r\n"
        "Content-Length: 0\r\n"
        "\r\n";

    HttpResponse response;
    int parsed = HttpParser::parse_response(
        reinterpret_cast<const uint8_t*>(http_data.data()),
        http_data.size(),
        response
    );

    std::cout << "Parsed bytes: " << parsed << std::endl;
    print_response(response);
}

int main() {
    std::cout << "\n╔════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║       NetGuardian HTTP Parser Demo                    ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════╝" << std::endl;

    try {
        // 运行所有测试
        test_simple_get_request();
        test_get_with_query();
        test_post_with_body();
        test_200_response();
        test_404_response();
        test_302_redirect();

        std::cout << "\n╔════════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║  All tests completed successfully!                    ║" << std::endl;
        std::cout << "╚════════════════════════════════════════════════════════╝\n" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
