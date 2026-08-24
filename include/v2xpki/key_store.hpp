#pragma once

// TODO: PKCS#11/HSM keystore backend.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "v2xpki/sizes.hpp"
#include "v2xpki/static_bytes.hpp"

namespace v2xpki {

// from() restricts id to [A-Za-z0-9_-] — backends use it as a filesystem path component.
class KeyHandle {
public:
    static std::optional<KeyHandle> from(const std::string& id) {
        if (id.empty()) return std::nullopt;
        for (char c : id) {
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                      c == '_' || c == '-';
            if (!ok) return std::nullopt;
        }
        auto sb = StaticBytes<64>::from(reinterpret_cast<const uint8_t*>(id.data()), id.size());
        if (!sb) return std::nullopt;
        KeyHandle h;
        h.id_ = *sb;
        return h;
    }

    std::string id_str() const { return {id_.begin(), id_.end()}; }

private:
    KeyHandle() = default;
    StaticBytes<64> id_;
};

// Sized for the largest supported curve (P-384); P-256 keys use a prefix of the capacity.
struct KeyPair {
    StaticBytes<kP384PublicKeyLen> public_key; // uncompressed point: 0x04 || X || Y
    StaticBytes<kP384ScalarLen> private_key; // raw scalar
};

struct Signature {
    StaticBytes<kP384ScalarLen> r;
    StaticBytes<kP384ScalarLen> s;
};

class KeyStore {
public:
    virtual ~KeyStore() = default;

    virtual std::optional<KeyPair> load_keypair(const KeyHandle& handle) = 0;
    virtual bool store_keypair(const KeyHandle& handle, const KeyPair& kp) = 0;

    virtual std::optional<Signature> sign(const KeyHandle& handle,
                                          const std::vector<uint8_t>& message) = 0;

    virtual std::optional<std::vector<uint8_t>> derive_shared_secret(const KeyHandle& handle,
                                                                     const std::vector<uint8_t>&
                                                                         peer_public_key) = 0;
};

} // namespace v2xpki
