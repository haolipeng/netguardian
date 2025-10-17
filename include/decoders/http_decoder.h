#ifndef NETGUARDIAN_DECODERS_HTTP_DECODER_H
#define NETGUARDIAN_DECODERS_HTTP_DECODER_H

#include "decoders/decoder_base.h"
#include <map>
#include <sstream>

namespace netguardian {
namespace decoders {

// HTTP 请求方法
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

// HTTP 消息类型
enum class HttpMessageType {
    UNKNOWN,
    REQUEST,
    RESPONSE
};

// HTTP 解码数据
class HttpData : public DecodedData {
public:
    HttpMessageType message_type;

    // 请求字段
    HttpMethod method;
    std::string method_str;
    std::string uri;
    std::string version;

    // 响应字段
    int status_code;
    std::string status_message;

    // 头部
    std::map<std::string, std::string> headers;

    // 主体（部分）
    std::string body;
    bool has_body;
    size_t content_length;

    HttpData()
        : message_type(HttpMessageType::UNKNOWN)
        , method(HttpMethod::UNKNOWN)
        , status_code(0)
        , has_body(false)
        , content_length(0)
    {}

    std::string to_string() const override {
        std::ostringstream oss;
        oss << "HTTP [";
        if (message_type == HttpMessageType::REQUEST) {
            oss << method_str << " " << uri << " " << version;
        } else if (message_type == HttpMessageType::RESPONSE) {
            oss << version << " " << status_code << " " << status_message;
        }
        oss << "]";
        return oss.str();
    }

    bool has_field(const std::string& field_name) const override {
        return field_name == "method" || field_name == "uri" ||
               field_name == "status_code" || field_name == "version" ||
               headers.find(field_name) != headers.end();
    }

    std::any get_field(const std::string& field_name) const override {
        if (field_name == "method") return method_str;
        if (field_name == "uri") return uri;
        if (field_name == "status_code") return status_code;
        if (field_name == "version") return version;

        auto it = headers.find(field_name);
        if (it != headers.end()) {
            return it->second;
        }
        return std::any();
    }

    std::string get_header(const std::string& name) const {
        auto it = headers.find(name);
        return (it != headers.end()) ? it->second : "";
    }

    static HttpMethod string_to_method(const std::string& str) {
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
};

// HTTP 解码器
class HttpDecoder : public DecoderBase {
public:
    std::shared_ptr<DecodedData> decode(const core::Packet& packet) override;
    std::string name() const override { return "HTTP"; }
    bool can_decode(const core::Packet& packet) const override;

private:
    bool parse_request(const char* data, size_t len, HttpData& http_data);
    bool parse_response(const char* data, size_t len, HttpData& http_data);
    void parse_headers(const char* data, size_t len, HttpData& http_data);
};

} // namespace decoders
} // namespace netguardian

#endif // NETGUARDIAN_DECODERS_HTTP_DECODER_H
