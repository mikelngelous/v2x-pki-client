#pragma once

#include "coer.hpp"

#include <cstdlib>
#include <utility>

extern "C" {
#include "asn_application.h"
}

namespace v2xpki {

template <class T> T* asn_calloc() { return static_cast<T*>(std::calloc(1, sizeof(T))); }

// Owning smart pointer for ASN.1 structures decoded by asn1c.
// Calls ASN_STRUCT_FREE(descriptor, ptr) on destruction.
template <typename T> class AsnPtr {
public:
    AsnPtr() noexcept = default;

    AsnPtr(const asn_TYPE_descriptor_t& desc, T* p) noexcept
        : ptr_(p)
        , desc_(&desc) {}

    ~AsnPtr() { reset(); }

    AsnPtr(AsnPtr&& o) noexcept
        : ptr_(o.ptr_)
        , desc_(o.desc_) {
        o.ptr_ = nullptr;
    }
    AsnPtr& operator=(AsnPtr&& o) noexcept {
        if (this != &o) {
            reset();
            ptr_ = o.ptr_;
            desc_ = o.desc_;
            o.ptr_ = nullptr;
        }
        return *this;
    }

    AsnPtr(const AsnPtr&) = delete;
    AsnPtr& operator=(const AsnPtr&) = delete;

    explicit operator bool() const noexcept { return ptr_ != nullptr; }
    T* get() const noexcept { return ptr_; }
    T* operator->() const noexcept { return ptr_; }
    T& operator*() const noexcept { return *ptr_; }

    T* release() noexcept {
        T* p = ptr_;
        ptr_ = nullptr;
        return p;
    }

    void reset() noexcept {
        if (ptr_) {
            ASN_STRUCT_FREE(*desc_, ptr_);
            ptr_ = nullptr;
        }
    }

private:
    T* ptr_ = nullptr;
    const asn_TYPE_descriptor_t* desc_ = nullptr;
};

// Convenience: COER-decode into AsnPtr.
template <typename T>
AsnPtr<T> asn_decode(const asn_TYPE_descriptor_t& desc, const uint8_t* buf, size_t len) {
    return AsnPtr<T>(desc, static_cast<T*>(coer::decode(&desc, buf, len)));
}

// Convenience: COER-decode with BASIC_OER fallback into AsnPtr.
template <typename T>
AsnPtr<T> asn_decode_fallback(const asn_TYPE_descriptor_t& desc, const uint8_t* buf, size_t len) {
    return AsnPtr<T>(desc, static_cast<T*>(coer::decode_with_basic_fallback(&desc, buf, len)));
}

} // namespace v2xpki
