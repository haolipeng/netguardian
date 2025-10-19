#ifndef NETGUARDIAN_UTILS_CXX11_COMPAT_H
#define NETGUARDIAN_UTILS_CXX11_COMPAT_H

#include <memory>
#include <utility>

namespace netguardian {
namespace utils {

// ============================================================================
// C++14 make_unique implementation for C++11
// ============================================================================

#if __cplusplus < 201402L

namespace detail {
    template<typename T>
    struct _Unique_if {
        typedef std::unique_ptr<T> _Single_object;
    };

    template<typename T>
    struct _Unique_if<T[]> {
        typedef std::unique_ptr<T[]> _Unknown_bound;
    };

    template<typename T, size_t N>
    struct _Unique_if<T[N]> {
        typedef void _Known_bound;
    };
}

// Single object version
template<typename T, typename... Args>
typename detail::_Unique_if<T>::_Single_object
make_unique(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

// Array version (unknown bound)
template<typename T>
typename detail::_Unique_if<T>::_Unknown_bound
make_unique(size_t n) {
    typedef typename std::remove_extent<T>::type U;
    return std::unique_ptr<T>(new U[n]());
}

// Deleted array version (known bound) - not allowed
template<typename T, typename... Args>
typename detail::_Unique_if<T>::_Known_bound
make_unique(Args&&...) = delete;

#else

// Use standard library version for C++14 and above
using std::make_unique;

#endif

} // namespace utils
} // namespace netguardian

#endif // NETGUARDIAN_UTILS_CXX11_COMPAT_H
