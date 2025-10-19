#ifndef NETGUARDIAN_UTILS_ANY_H
#define NETGUARDIAN_UTILS_ANY_H

#include <typeinfo>
#include <stdexcept>
#include <utility>

namespace netguardian {
namespace utils {

// ============================================================================
// Simple any implementation for C++11 (replacement for std::any)
// ============================================================================

class bad_any_cast : public std::bad_cast {
public:
    const char* what() const noexcept override {
        return "bad any_cast";
    }
};

class any {
public:
    // Constructors
    any() : content_(nullptr) {}

    template<typename ValueType>
    any(const ValueType& value)
        : content_(new holder<typename std::decay<ValueType>::type>(value))
    {}

    any(const any& other)
        : content_(other.content_ ? other.content_->clone() : nullptr)
    {}

    any(any&& other) noexcept
        : content_(other.content_)
    {
        other.content_ = nullptr;
    }

    // Destructor
    ~any() {
        delete content_;
    }

    // Assignment operators
    any& operator=(const any& rhs) {
        if (this != &rhs) {
            any(rhs).swap(*this);
        }
        return *this;
    }

    any& operator=(any&& rhs) noexcept {
        if (this != &rhs) {
            delete content_;
            content_ = rhs.content_;
            rhs.content_ = nullptr;
        }
        return *this;
    }

    template<typename ValueType>
    any& operator=(const ValueType& rhs) {
        any(rhs).swap(*this);
        return *this;
    }

    template<typename ValueType>
    any& operator=(ValueType&& rhs) {
        any(std::forward<ValueType>(rhs)).swap(*this);
        return *this;
    }

    // Modifiers
    void reset() noexcept {
        delete content_;
        content_ = nullptr;
    }

    void swap(any& rhs) noexcept {
        std::swap(content_, rhs.content_);
    }

    // Observers
    bool has_value() const noexcept {
        return content_ != nullptr;
    }

    const std::type_info& type() const noexcept {
        return content_ ? content_->type() : typeid(void);
    }

private:
    class placeholder {
    public:
        virtual ~placeholder() {}
        virtual const std::type_info& type() const noexcept = 0;
        virtual placeholder* clone() const = 0;
    };

    template<typename ValueType>
    class holder : public placeholder {
    public:
        holder(const ValueType& value) : held_(value) {}

        holder(ValueType&& value) : held_(std::move(value)) {}

        const std::type_info& type() const noexcept override {
            return typeid(ValueType);
        }

        placeholder* clone() const override {
            return new holder(held_);
        }

        ValueType held_;
    };

    placeholder* content_;

    template<typename ValueType>
    friend ValueType* any_cast(any*) noexcept;

    template<typename ValueType>
    friend const ValueType* any_cast(const any*) noexcept;
};

// any_cast implementations
template<typename ValueType>
ValueType* any_cast(any* operand) noexcept {
    if (operand && operand->type() == typeid(ValueType)) {
        return &static_cast<any::holder<typename std::remove_cv<ValueType>::type>*>(
            operand->content_)->held_;
    }
    return nullptr;
}

template<typename ValueType>
const ValueType* any_cast(const any* operand) noexcept {
    return any_cast<ValueType>(const_cast<any*>(operand));
}

template<typename ValueType>
ValueType any_cast(any& operand) {
    typedef typename std::remove_reference<ValueType>::type nonref;

    nonref* result = any_cast<nonref>(&operand);
    if (!result) {
        throw bad_any_cast();
    }

    typedef typename std::conditional<
        std::is_reference<ValueType>::value,
        ValueType,
        typename std::add_lvalue_reference<ValueType>::type
    >::type ref_type;

    return static_cast<ref_type>(*result);
}

template<typename ValueType>
ValueType any_cast(const any& operand) {
    typedef typename std::remove_reference<ValueType>::type nonref;

    return any_cast<const nonref&>(const_cast<any&>(operand));
}

template<typename ValueType>
ValueType any_cast(any&& operand) {
    typedef typename std::remove_reference<ValueType>::type nonref;

    nonref* result = any_cast<nonref>(&operand);
    if (!result) {
        throw bad_any_cast();
    }

    typedef typename std::conditional<
        std::is_reference<ValueType>::value,
        ValueType,
        typename std::add_rvalue_reference<ValueType>::type
    >::type ref_type;

    return static_cast<ref_type>(std::move(*result));
}

// Factory function
template<typename T, typename... Args>
any make_any(Args&&... args) {
    return any(T(std::forward<Args>(args)...));
}

} // namespace utils
} // namespace netguardian

#endif // NETGUARDIAN_UTILS_ANY_H
