#pragma once

#include <optional>
#include <variant>

namespace v2xpki {

enum class Error {
    None = 0,
    InvalidArgument,   // bad input (key size, malformed param)
    Network,           // connect/resolve/timeout — no HTTP response
    HttpStatus,        // got HTTP response with non-2xx status
    Decode,            // ASN.1 / COER decode failure
    Encode,            // encoding failure
    Crypto,            // ECDSA/ECIES/keygen failure
    SignatureInvalid,  // signature verification failed
    NotFound,          // entity absent (trust chain, server)
    KeyStore,          // keystore read/write failure
    Protocol,          // server response_code != 0 / unexpected content
};

inline constexpr const char* to_string(Error e) noexcept {
    switch (e) {
        case Error::None:             return "none";
        case Error::InvalidArgument:  return "invalid argument";
        case Error::Network:          return "network";
        case Error::HttpStatus:       return "http status";
        case Error::Decode:           return "decode";
        case Error::Encode:           return "encode";
        case Error::Crypto:           return "crypto";
        case Error::SignatureInvalid: return "signature invalid";
        case Error::NotFound:         return "not found";
        case Error::KeyStore:         return "keystore";
        case Error::Protocol:         return "protocol";
    }
    return "unknown";
}

template <class T>
class Result {
public:
    Result(T v) : value_(std::move(v)), error_(Error::None) {}
    Result(Error e) : error_(e) {}

    bool has_value() const noexcept { return value_.has_value(); }
    explicit operator bool() const noexcept { return value_.has_value(); }

    const T& value() const& { return *value_; }
    T&& value() && { return std::move(*value_); }

    const T* operator->() const { return &*value_; }
    const T& operator*() const& { return *value_; }

    Error error() const noexcept { return error_; }

private:
    std::optional<T> value_;
    Error error_ = Error::None;
};

using Status = Result<std::monostate>;

}  // namespace v2xpki
