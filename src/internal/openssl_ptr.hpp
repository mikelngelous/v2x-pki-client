// OpenSSL smart-pointer aliases — shared by crypto_ec.cpp and ecies.cpp.

#pragma once

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include <memory>

namespace v2xpki::ssl {

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY *p) const { EVP_PKEY_free(p); }
};
struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX *p) const { EVP_PKEY_CTX_free(p); }
};
struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX *p) const { EVP_MD_CTX_free(p); }
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
struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX *p) const { EVP_CIPHER_CTX_free(p); }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
using BnCtxPtr = std::unique_ptr<BN_CTX, BnCtxDeleter>;
using EcGroupPtr = std::unique_ptr<EC_GROUP, EcGroupDeleter>;
using EcPointPtr = std::unique_ptr<EC_POINT, EcPointDeleter>;
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

} // namespace v2xpki::ssl
