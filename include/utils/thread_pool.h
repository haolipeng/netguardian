#ifndef NETGUARDIAN_UTILS_THREAD_POOL_H
#define NETGUARDIAN_UTILS_THREAD_POOL_H

#include <vector>
#include <thread>
#include <queue>
#include <functional>
<mutex>
#include <condition_variable>
#include <atomic>
#include <future>

namespace netguardian {
namespace utils {

/**
 * 简单的线程池实现
 * 用于并发处理数据包
 */
class ThreadPool {
public:
    /**
     * 构造函数
     * @param num_threads 线程数量，0表示使用硬件并发数
     */
    explicit ThreadPool(size_t num_threads = 0)
        : stop_(false)
    {
        if (num_threads == 0) {
            num_threads = std::thread::hardware_concurrency();
            if (num_threads == 0) {
                num_threads = 4;  // 默认4个线程
            }
        }

        workers_.reserve(num_threads);
        for (size_t i = 0; i < num_threads; ++i) {
            workers_.emplace_back([this, i] {
                this->worker_thread(i);
            });
        }
    }

    /**
     * 析构函数 - 等待所有任务完成并停止所有线程
     */
    ~ThreadPool() {
        shutdown();
    }

    // 禁止拷贝
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    /**
     * 提交任务到线程池
     * @param func 要执行的函数
     * @param args 函数参数
     * @return future 用于获取函数返回值
     */
    template<typename Func, typename... Args>
    auto submit(Func&& func, Args&&... args)
        -> std::future<typename std::result_of<Func(Args...)>::type>
    {
        using return_type = typename std::result_of<Func(Args...)>::type;

        auto task = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<Func>(func), std::forward<Args>(args)...)
        );

        std::future<return_type> result = task->get_future();

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);

            if (stop_) {
                throw std::runtime_error("ThreadPool is stopped");
            }

            tasks_.emplace([task]() { (*task)(); });
        }

        queue_cv_.notify_one();
        return result;
    }

    /**
     * 提交任务但不返回future（更高效）
     */
    void submit_detached(std::function<void()> task) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);

            if (stop_) {
                return;
            }

            tasks_.emplace(std::move(task));
        }

        queue_cv_.notify_one();
    }

    /**
     * 获取线程池中的线程数量
     */
    size_t num_threads() const {
        return workers_.size();
    }

    /**
     * 获取待处理任务数量
     */
    size_t pending_tasks() const {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        return tasks_.size();
    }

    /**
     * 关闭线程池
     */
    void shutdown() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (stop_) {
                return;
            }
            stop_ = true;
        }

        queue_cv_.notify_all();

        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }

        workers_.clear();
    }

    /**
     * 等待所有任务完成
     */
    void wait_all() {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        all_done_cv_.wait(lock, [this] {
            return tasks_.empty() && active_workers_ == 0;
        });
    }

private:
    /**
     * 工作线程函数
     */
    void worker_thread(size_t id) {
        (void)id;  // 可用于调试

        while (true) {
            std::function<void()> task;

            {
                std::unique_lock<std::mutex> lock(queue_mutex_);

                queue_cv_.wait(lock, [this] {
                    return stop_ || !tasks_.empty();
                });

                if (stop_ && tasks_.empty()) {
                    return;
                }

                if (!tasks_.empty()) {
                    task = std::move(tasks_.front());
                    tasks_.pop();
                    active_workers_++;
                }
            }

            if (task) {
                task();

                {
                    std::unique_lock<std::mutex> lock(queue_mutex_);
                    active_workers_--;
                    if (tasks_.empty() && active_workers_ == 0) {
                        all_done_cv_.notify_all();
                    }
                }
            }
        }
    }

    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;

    mutable std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::condition_variable all_done_cv_;

    std::atomic<bool> stop_;
    std::atomic<size_t> active_workers_{0};
};

} // namespace utils
} // namespace netguardian

#endif // NETGUARDIAN_UTILS_THREAD_POOL_H
