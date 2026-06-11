#pragma once

// !! DEV ONLY — KEYS STORED IN PLAINTEXT ON DISK. DO NOT USE IN PRODUCTION. !!

#include <filesystem>
#include <string>

#include "v2xpki/key_store.hpp"

namespace v2xpki {

class PlaintextFileKeyStore final : public KeyStore {
public:
    explicit PlaintextFileKeyStore(std::filesystem::path keystore_dir);

    std::optional<KeyPair> load_keypair(const KeyHandle& handle) override;
    bool store_keypair(const KeyHandle& handle, const KeyPair& kp) override;

    std::optional<Signature> sign(const KeyHandle& handle,
                                  const std::vector<uint8_t>& message) override;

    std::optional<std::vector<uint8_t>> derive_shared_secret(const KeyHandle& handle,
                                                             const std::vector<uint8_t>&
                                                                 peer_public_key) override;

private:
    std::filesystem::path dir_;
    std::filesystem::path pem_path(const KeyHandle& handle) const;
};

} // namespace v2xpki
