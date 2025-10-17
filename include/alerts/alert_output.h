#ifndef NETGUARDIAN_ALERTS_ALERT_OUTPUT_H
#define NETGUARDIAN_ALERTS_ALERT_OUTPUT_H

#include "alerts/alert.h"
#include <memory>
#include <fstream>
#include <iostream>
#include <mutex>
#include <syslog.h>

namespace netguardian {
namespace alerts {

// 告警输出器接口
class AlertOutput {
public:
    virtual ~AlertOutput() = default;

    // 输出告警
    virtual void output(const Alert& alert) = 0;

    // 刷新缓冲区
    virtual void flush() {}

    // 关闭输出器
    virtual void close() {}
};

// 控制台输出器
class ConsoleAlertOutput : public AlertOutput {
public:
    enum class ColorMode {
        NONE,     // 无颜色
        BASIC,    // 基本颜色
        EXTENDED  // 扩展颜色（256 色）
    };

    explicit ConsoleAlertOutput(ColorMode mode = ColorMode::BASIC)
        : color_mode_(mode)
    {}

    void output(const Alert& alert) override {
        std::lock_guard<std::mutex> lock(mutex_);

        if (color_mode_ != ColorMode::NONE) {
            std::cout << get_priority_color(alert.priority);
        }

        std::cout << alert.to_string();

        if (color_mode_ != ColorMode::NONE) {
            std::cout << "\033[0m";  // 重置颜色
        }

        std::cout << std::endl;
    }

    void flush() override {
        std::cout.flush();
    }

private:
    ColorMode color_mode_;
    std::mutex mutex_;

    // 根据优先级获取颜色代码
    std::string get_priority_color(AlertPriority priority) {
        switch (priority) {
            case AlertPriority::CRITICAL:
                return "\033[1;91m";  // 亮红色
            case AlertPriority::HIGH:
                return "\033[1;31m";  // 红色
            case AlertPriority::MEDIUM:
                return "\033[1;33m";  // 黄色
            case AlertPriority::LOW:
                return "\033[1;36m";  // 青色
            default:
                return "\033[0m";     // 默认
        }
    }
};

// 文件输出器
class FileAlertOutput : public AlertOutput {
public:
    enum class FileFormat {
        TEXT,  // 纯文本格式
        JSON,  // JSON 格式
        CSV    // CSV 格式
    };

    FileAlertOutput(const std::string& filename, FileFormat format = FileFormat::TEXT)
        : filename_(filename)
        , format_(format)
        , first_record_(true)
    {
        file_.open(filename_, std::ios::out | std::ios::app);
        if (!file_.is_open()) {
            throw std::runtime_error("Failed to open alert file: " + filename_);
        }

        // CSV 格式需要写入表头
        if (format_ == FileFormat::CSV && is_new_file()) {
            file_ << Alert::csv_header() << std::endl;
        }

        // JSON 格式开始数组
        if (format_ == FileFormat::JSON) {
            file_ << "[\n";
        }
    }

    ~FileAlertOutput() override {
        close();
    }

    void output(const Alert& alert) override {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!file_.is_open()) {
            return;
        }

        switch (format_) {
            case FileFormat::TEXT:
                file_ << alert.to_string() << std::endl;
                break;

            case FileFormat::JSON:
                if (!first_record_) {
                    file_ << ",\n";
                }
                file_ << alert.to_json();
                first_record_ = false;
                break;

            case FileFormat::CSV:
                file_ << alert.to_csv() << std::endl;
                break;
        }
    }

    void flush() override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open()) {
            file_.flush();
        }
    }

    void close() override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open()) {
            // JSON 格式结束数组
            if (format_ == FileFormat::JSON) {
                file_ << "\n]\n";
            }
            file_.close();
        }
    }

private:
    std::string filename_;
    FileFormat format_;
    std::ofstream file_;
    bool first_record_;
    std::mutex mutex_;

    // 检查是否为新文件
    bool is_new_file() {
        std::ifstream test(filename_);
        bool exists = test.good();
        test.close();
        return !exists;
    }
};

// Syslog 输出器
class SyslogAlertOutput : public AlertOutput {
public:
    SyslogAlertOutput(const std::string& ident = "netguardian", int facility = LOG_LOCAL0) {
        openlog(ident.c_str(), LOG_PID | LOG_CONS, facility);
    }

    ~SyslogAlertOutput() override {
        closelog();
    }

    void output(const Alert& alert) override {
        int priority = get_syslog_priority(alert.priority);

        // 格式化消息
        std::ostringstream oss;
        oss << "[SID:" << alert.signature_id << ":" << alert.revision << "] "
            << alert.message << " | "
            << alert.src_ip << ":" << alert.src_port << " -> "
            << alert.dst_ip << ":" << alert.dst_port;

        syslog(priority, "%s", oss.str().c_str());
    }

private:
    // 将告警优先级转换为 syslog 优先级
    int get_syslog_priority(AlertPriority priority) {
        switch (priority) {
            case AlertPriority::CRITICAL:
                return LOG_CRIT;
            case AlertPriority::HIGH:
                return LOG_ERR;
            case AlertPriority::MEDIUM:
                return LOG_WARNING;
            case AlertPriority::LOW:
                return LOG_INFO;
            default:
                return LOG_NOTICE;
        }
    }
};

// 组合输出器（支持多个输出目标）
class MultiAlertOutput : public AlertOutput {
public:
    void add_output(std::shared_ptr<AlertOutput> output) {
        std::lock_guard<std::mutex> lock(mutex_);
        outputs_.push_back(output);
    }

    void output(const Alert& alert) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& output : outputs_) {
            output->output(alert);
        }
    }

    void flush() override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& output : outputs_) {
            output->flush();
        }
    }

    void close() override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& output : outputs_) {
            output->close();
        }
    }

private:
    std::vector<std::shared_ptr<AlertOutput>> outputs_;
    std::mutex mutex_;
};

} // namespace alerts
} // namespace netguardian

#endif // NETGUARDIAN_ALERTS_ALERT_OUTPUT_H
