#pragma once

// TODO: PKCS#11/HSM keystore backend.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace v2xpki {

struct KeyHandle {
    std::string id;
};

struct KeyPair {
    std::vector<uint8_t> public_key; // uncompressed point: 0x04 || X(32) || Y(32) = 65 bytes
    std::vector<uint8_t> private_key; // raw scalar: 32 bytes P-256
};

struct Signature {
    std::vector<uint8_t> r; // 32 bytes
    std::vector<uint8_t> s; // 32 bytes
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
