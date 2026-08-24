#pragma once

// Fixed-capacity byte buffer with a runtime length — no heap allocation.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace v2xpki {

template <size_t N> class StaticBytes {
public:
    StaticBytes() = default;

    static std::optional<StaticBytes> from(const uint8_t* p, size_t n) {
        if (n > N) return std::nullopt;
        StaticBytes b;
        std::copy_n(p, n, b.data_.begin());
        b.len_ = n;
        return b;
    }

    static std::optional<StaticBytes> from(const std::vector<uint8_t>& v) {
        return from(v.data(), v.size());
    }

    std::vector<uint8_t> to_vector() const { return std::vector<uint8_t>(begin(), end()); }

    static constexpr size_t capacity() { return N; }

    const uint8_t* data() const { return data_.data(); }
    size_t size() const { return len_; }
    bool empty() const { return len_ == 0; }
    uint8_t operator[](size_t i) const { return data_[i]; }
    void clear() { len_ = 0; }

    auto begin() const { return data_.begin(); }
    auto end() const { return data_.begin() + static_cast<std::ptrdiff_t>(len_); }

    bool operator==(const StaticBytes& other) const {
        return len_ == other.len_ && std::equal(begin(), end(), other.begin());
    }
    bool operator!=(const StaticBytes& other) const { return !(*this == other); }

    bool operator==(const std::vector<uint8_t>& other) const {
        return len_ == other.size() && std::equal(begin(), end(), other.begin());
    }
    bool operator!=(const std::vector<uint8_t>& other) const { return !(*this == other); }

private:
    std::array<uint8_t, N> data_{};
    size_t len_ = 0;
};

template <size_t N> bool operator==(const std::vector<uint8_t>& a, const StaticBytes<N>& b) {
    return b == a;
}
template <size_t N> bool operator!=(const std::vector<uint8_t>& a, const StaticBytes<N>& b) {
    return !(b == a);
}

} // namespace v2xpki
