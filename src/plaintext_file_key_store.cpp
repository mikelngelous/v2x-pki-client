// !! DEV ONLY — KEYS STORED IN PLAINTEXT ON DISK !!

#include "v2xpki/plaintext_file_key_store.hpp"
#include "v2xpki/sizes.hpp"
#include "v2xpki/static_bytes.hpp"
#include "v2xpki/crypto_ec.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>

#include <cstdio>
#include <memory>

namespace v2xpki {

namespace {

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY *p) const { EVP_PKEY_free(p); }
};
struct BnDeleter {
    void operator()(BIGNUM *p) const { BN_free(p); }
};
struct BnCtxDeleter {
    void operator()(BN_CTX *p) const { BN_CTX_free(p); }
};
struct EcGroupDeleter {
    void operator()(EC_GROUP *p) const { EC_GROUP_free(p); }
};
struct EcPointDeleter {
    void operator()(EC_POINT *p) const { EC_POINT_free(p); }
};
struct FileDeleter {
    void operator()(FILE *f) const {
        if (f) fclose(f);
    }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using FilePtr = std::unique_ptr<FILE, FileDeleter>;

// Try to build EVP_PKEY from raw keypair with a given group name.
EvpPkeyPtr try_build_pkey(const KeyPair &kp, const char *group_name) {
    std::unique_ptr<BIGNUM, BnDeleter> bn_priv(BN_bin2bn(kp.private_key.data(),
                                                         static_cast<int>(kp.private_key.size()),
                                                         nullptr));
    if (!bn_priv) return nullptr;

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) return nullptr;

    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bn_priv.get());
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, kp.public_key.data(),
                                     kp.public_key.size());

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) return nullptr;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY *pkey = nullptr;
    int ok = EVP_PKEY_fromdata_init(ctx) > 0 &&
             EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) > 0;
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);

    if (!ok) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }
    return EvpPkeyPtr(pkey);
}

// Build EVP_PKEY from raw keypair, auto-detecting the curve.
EvpPkeyPtr build_pkey(const KeyPair &kp) {
    if (kp.public_key.size() == kP384PublicKeyLen && kp.private_key.size() == kP384ScalarLen) {
        return try_build_pkey(kp, "brainpoolP384r1");
    }
    if (kp.public_key.size() == kP256PublicKeyLen && kp.private_key.size() == kP256ScalarLen) {
        // Try NIST P-256 first, then Brainpool P-256r1
        auto pkey = try_build_pkey(kp, "prime256v1");
        if (pkey) return pkey;
        return try_build_pkey(kp, "brainpoolP256r1");
    }
    return nullptr;
}

// Extract KeyPair from EVP_PKEY
std::optional<KeyPair> extract_keypair(EVP_PKEY *pkey) {
    BIGNUM *bn_priv = nullptr;
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv)) return std::nullopt;
    std::unique_ptr<BIGNUM, BnDeleter> priv_guard(bn_priv);

    // Determine scalar size from the actual key bits
    int bits = EVP_PKEY_get_bits(pkey);
    size_t slen = (bits > 256) ? kP384ScalarLen : kP256ScalarLen;

    std::vector<uint8_t> priv_bytes(slen);
    BN_bn2binpad(bn_priv, priv_bytes.data(), static_cast<int>(slen));

    size_t pub_len = 0;
    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pub_len))
        return std::nullopt;
    std::vector<uint8_t> pub_bytes(pub_len);
    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub_bytes.data(),
                                         pub_bytes.size(), &pub_len))
        return std::nullopt;
    pub_bytes.resize(pub_len);

    auto pub_sb = StaticBytes<kP384PublicKeyLen>::from(pub_bytes);
    auto priv_sb = StaticBytes<kP384ScalarLen>::from(priv_bytes);
    if (!pub_sb || !priv_sb) return std::nullopt;
    return KeyPair{*pub_sb, *priv_sb};
}

}

PlaintextFileKeyStore::PlaintextFileKeyStore(std::filesystem::path keystore_dir)
    : dir_(std::move(keystore_dir)) {
    std::filesystem::create_directories(dir_);
}

std::filesystem::path PlaintextFileKeyStore::pem_path(const KeyHandle &handle) const {
    return dir_ / (handle.id_str() + ".pem");
}

std::optional<KeyPair> PlaintextFileKeyStore::load_keypair(const KeyHandle &handle) {
    auto path = pem_path(handle);
    FilePtr fp(fopen(path.c_str(), "r"));
    if (!fp) return std::nullopt;

    EVP_PKEY *raw = PEM_read_PrivateKey(fp.get(), nullptr, nullptr, nullptr);
    if (!raw) return std::nullopt;
    EvpPkeyPtr pkey(raw);

    return extract_keypair(pkey.get());
}

bool PlaintextFileKeyStore::store_keypair(const KeyHandle &handle, const KeyPair &kp) {
    auto pkey = build_pkey(kp);
    if (!pkey) return false;

    auto path = pem_path(handle);
    FilePtr fp(fopen(path.c_str(), "w"));
    if (!fp) return false;

    return PEM_write_PrivateKey(fp.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1;
}

std::optional<Signature> PlaintextFileKeyStore::sign(const KeyHandle &handle,
                                                     const std::vector<uint8_t> &message) {

    auto kp = load_keypair(handle);
    if (!kp) return std::nullopt;

    return crypto::ecdsa_sign(kp->private_key.to_vector(), message);
}

std::optional<std::vector<uint8_t>> PlaintextFileKeyStore::
    derive_shared_secret(const KeyHandle &handle, const std::vector<uint8_t> &peer_public_key) {

    auto kp = load_keypair(handle);
    if (!kp) return std::nullopt;

    return crypto::ecdh_derive(kp->private_key.to_vector(), peer_public_key);
}

} // namespace v2xpki
