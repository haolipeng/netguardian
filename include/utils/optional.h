#ifndef NETGUARDIAN_UTILS_OPTIONAL_H
#define NETGUARDIAN_UTILS_OPTIONAL_H

#include <stdexcept>
#include <utility>

namespace netguardian {
namespace utils {

// ============================================================================
// Simple optional implementation for C++11 (replacement for std::optional)
// ============================================================================

struct nullopt_t {
    explicit constexpr nullopt_t(int) {}
};

constexpr nullopt_t nullopt{0};

class bad_optional_access : public std::logic_error {
public:
    bad_optional_access() : std::logic_error("bad optional access") {}
};

template<typename T>
class optional {
public:
    // Constructors
    optional() : has_value_(false) {}

    optional(nullopt_t) : has_value_(false) {}

    optional(const T& value) : has_value_(true) {
        new (&storage_) T(value);
    }

    optional(T&& value) : has_value_(true) {
        new (&storage_) T(std::move(value));
    }

    // Copy constructor
    optional(const optional& other) : has_value_(other.has_value_) {
        if (has_value_) {
            new (&storage_) T(*other.ptr());
        }
    }

    // Move constructor
    optional(optional&& other) : has_value_(other.has_value_) {
        if (has_value_) {
            new (&storage_) T(std::move(*other.ptr()));
        }
    }

    // Destructor
    ~optional() {
        reset();
    }

    // Assignment operators
    optional& operator=(nullopt_t) {
        reset();
        return *this;
    }

    optional& operator=(const optional& other) {
        if (this != &other) {
            if (other.has_value_) {
                if (has_value_) {
                    *ptr() = *other.ptr();
                } else {
                    new (&storage_) T(*other.ptr());
                    has_value_ = true;
                }
            } else {
                reset();
            }
        }
        return *this;
    }

    optional& operator=(optional&& other) {
        if (this != &other) {
            if (other.has_value_) {
                if (has_value_) {
                    *ptr() = std::move(*other.ptr());
                } else {
                    new (&storage_) T(std::move(*other.ptr()));
                    has_value_ = true;
                }
            } else {
                reset();
            }
        }
        return *this;
    }

    optional& operator=(const T& value) {
        if (has_value_) {
            *ptr() = value;
        } else {
            new (&storage_) T(value);
            has_value_ = true;
        }
        return *this;
    }

    optional& operator=(T&& value) {
        if (has_value_) {
            *ptr() = std::move(value);
        } else {
            new (&storage_) T(std::move(value));
            has_value_ = true;
        }
        return *this;
    }

    // Observers
    const T* operator->() const {
        return ptr();
    }

    T* operator->() {
        return ptr();
    }

    const T& operator*() const& {
        return *ptr();
    }

    T& operator*() & {
        return *ptr();
    }

    T&& operator*() && {
        return std::move(*ptr());
    }

    explicit operator bool() const {
        return has_value_;
    }

    bool has_value() const {
        return has_value_;
    }

    const T& value() const& {
        if (!has_value_) {
            throw bad_optional_access();
        }
        return *ptr();
    }

    T& value() & {
        if (!has_value_) {
            throw bad_optional_access();
        }
        return *ptr();
    }

    T&& value() && {
        if (!has_value_) {
            throw bad_optional_access();
        }
        return std::move(*ptr());
    }

    template<typename U>
    T value_or(U&& default_value) const& {
        return has_value_ ? *ptr() : static_cast<T>(std::forward<U>(default_value));
    }

    template<typename U>
    T value_or(U&& default_value) && {
        return has_value_ ? std::move(*ptr()) : static_cast<T>(std::forward<U>(default_value));
    }

    // Modifiers
    void reset() {
        if (has_value_) {
            ptr()->~T();
            has_value_ = false;
        }
    }

    template<typename... Args>
    void emplace(Args&&... args) {
        reset();
        new (&storage_) T(std::forward<Args>(args)...);
        has_value_ = true;
    }

private:
    T* ptr() {
        return reinterpret_cast<T*>(&storage_);
    }

    const T* ptr() const {
        return reinterpret_cast<const T*>(&storage_);
    }

    typename std::aligned_storage<sizeof(T), alignof(T)>::type storage_;
    bool has_value_;
};

// Comparison operators
template<typename T>
bool operator==(const optional<T>& lhs, const optional<T>& rhs) {
    if (lhs.has_value() != rhs.has_value()) {
        return false;
    }
    if (!lhs.has_value()) {
        return true;
    }
    return *lhs == *rhs;
}

template<typename T>
bool operator!=(const optional<T>& lhs, const optional<T>& rhs) {
    return !(lhs == rhs);
}

template<typename T>
bool operator==(const optional<T>& opt, nullopt_t) {
    return !opt.has_value();
}

template<typename T>
bool operator==(nullopt_t, const optional<T>& opt) {
    return !opt.has_value();
}

template<typename T>
bool operator!=(const optional<T>& opt, nullopt_t) {
    return opt.has_value();
}

template<typename T>
bool operator!=(nullopt_t, const optional<T>& opt) {
    return opt.has_value();
}

// Factory function
template<typename T>
optional<typename std::decay<T>::type> make_optional(T&& value) {
    return optional<typename std::decay<T>::type>(std::forward<T>(value));
}

} // namespace utils
} // namespace netguardian

#endif // NETGUARDIAN_UTILS_OPTIONAL_H
