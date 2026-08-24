#include "v2xpki/crypto_ec.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>

#include "v2xpki/sizes.hpp"
#include "v2xpki/static_bytes.hpp"
#include "internal/openssl_ptr.hpp"

namespace v2xpki::crypto {

namespace {

using namespace v2xpki::ssl;

EvpPkeyPtr evp_pkey_from_private(const std::vector<uint8_t>& priv, Curve curve) {
    auto slen = scalar_len(curve);
    auto plen = pubkey_len(curve);
    if (priv.size() != slen) return nullptr;

    int nid = curve_nid(curve);
    EcGroupPtr group(EC_GROUP_new_by_curve_name(nid));
    if (!group) return nullptr;

    BnPtr bn_priv(BN_bin2bn(priv.data(), static_cast<int>(priv.size()), nullptr));
    if (!bn_priv) return nullptr;

    BnCtxPtr bn_ctx(BN_CTX_new());
    EcPointPtr pub_point(EC_POINT_new(group.get()));
    if (!EC_POINT_mul(group.get(), pub_point.get(), bn_priv.get(), nullptr, nullptr, bn_ctx.get()))
        return nullptr;

    std::vector<uint8_t> pub_buf(plen);
    if (EC_POINT_point2oct(group.get(), pub_point.get(), POINT_CONVERSION_UNCOMPRESSED,
                           pub_buf.data(), pub_buf.size(), bn_ctx.get()) != plen)
        return nullptr;

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) return nullptr;

    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                    const_cast<char*>(curve_group_name(curve)), 0);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bn_priv.get());
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_buf.data(), pub_buf.size());

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) return nullptr;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY* pkey = nullptr;
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

EvpPkeyPtr evp_pkey_from_public(const std::vector<uint8_t>& pub, Curve curve) {
    auto plen = pubkey_len(curve);
    auto clen = compressed_len(curve);

    bool uncompressed = (pub.size() == plen && pub[0] == 0x04);
    bool compressed = (pub.size() == clen && (pub[0] == 0x02 || pub[0] == 0x03));
    if (!uncompressed && !compressed) return nullptr;

    int nid = curve_nid(curve);
    std::vector<uint8_t> uncompressed_pub;
    if (compressed) {
        EcGroupPtr group(EC_GROUP_new_by_curve_name(nid));
        if (!group) return nullptr;
        BnCtxPtr bn_ctx(BN_CTX_new());
        if (!bn_ctx) return nullptr;
        EcPointPtr point(EC_POINT_new(group.get()));
        if (!point) return nullptr;
        if (!EC_POINT_oct2point(group.get(), point.get(), pub.data(), pub.size(), bn_ctx.get()))
            return nullptr;
        uncompressed_pub.resize(plen);
        if (EC_POINT_point2oct(group.get(), point.get(), POINT_CONVERSION_UNCOMPRESSED,
                               uncompressed_pub.data(), plen, bn_ctx.get()) != plen)
            return nullptr;
    } else {
        uncompressed_pub = pub;
    }

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) return nullptr;

    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                    const_cast<char*>(curve_group_name(curve)), 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, uncompressed_pub.data(),
                                     uncompressed_pub.size());

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) return nullptr;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY* pkey = nullptr;
    int ok = EVP_PKEY_fromdata_init(ctx) > 0 &&
             EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) > 0;
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);

    if (!ok) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }
    return EvpPkeyPtr(pkey);
}

bool extract_rs_from_der(const uint8_t* der, size_t der_len, Signature& sig_out, std::size_t slen) {
    const uint8_t* p = der;
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der_len));
    if (!sig) return false;

    const BIGNUM* r_bn = nullptr;
    const BIGNUM* s_bn = nullptr;
    ECDSA_SIG_get0(sig, &r_bn, &s_bn);

    std::array<uint8_t, kP384ScalarLen> r_buf{};
    std::array<uint8_t, kP384ScalarLen> s_buf{};
    BN_bn2binpad(r_bn, r_buf.data(), static_cast<int>(slen));
    BN_bn2binpad(s_bn, s_buf.data(), static_cast<int>(slen));
    ECDSA_SIG_free(sig);

    auto r_sb = StaticBytes<kP384ScalarLen>::from(r_buf.data(), slen);
    auto s_sb = StaticBytes<kP384ScalarLen>::from(s_buf.data(), slen);
    if (!r_sb || !s_sb) return false;
    sig_out.r = *r_sb;
    sig_out.s = *s_sb;
    return true;
}

std::vector<uint8_t> build_der_from_rs(const uint8_t* r, size_t rlen, const uint8_t* s,
                                       size_t slen) {
    ECDSA_SIG* sig = ECDSA_SIG_new();
    if (!sig) return {};
    BIGNUM* r_bn = BN_bin2bn(r, static_cast<int>(rlen), nullptr);
    BIGNUM* s_bn = BN_bin2bn(s, static_cast<int>(slen), nullptr);
    if (!r_bn || !s_bn) {
        BN_free(r_bn);
        BN_free(s_bn);
        ECDSA_SIG_free(sig);
        return {};
    }
    ECDSA_SIG_set0(sig, r_bn, s_bn); // takes ownership

    int der_len = i2d_ECDSA_SIG(sig, nullptr);
    if (der_len <= 0) {
        ECDSA_SIG_free(sig);
        return {};
    }
    std::vector<uint8_t> der(der_len);
    uint8_t* p = der.data();
    i2d_ECDSA_SIG(sig, &p);

    ECDSA_SIG_free(sig);
    return der;
}

}

// ============ Curve helpers ============

int curve_nid(Curve curve) noexcept {
    switch (curve) {
        case Curve::NistP256: return NID_X9_62_prime256v1;
        case Curve::BrainpoolP256r1: return NID_brainpoolP256r1;
        case Curve::NistP384: return NID_secp384r1;
        case Curve::BrainpoolP384r1: return NID_brainpoolP384r1;
    }
    return NID_X9_62_prime256v1;
}

const char* curve_group_name(Curve curve) noexcept {
    switch (curve) {
        case Curve::NistP256: return "prime256v1";
        case Curve::BrainpoolP256r1: return "brainpoolP256r1";
        case Curve::NistP384: return "secp384r1";
        case Curve::BrainpoolP384r1: return "brainpoolP384r1";
    }
    return "prime256v1";
}

// ============ Key generation ============

std::optional<KeyPair> generate_keypair() { return generate_keypair(Curve::NistP256); }

std::optional<KeyPair> generate_keypair(Curve curve) {
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!ctx) return std::nullopt;

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) return std::nullopt;

    OSSL_PARAM params[] =
        {OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                          const_cast<char*>(curve_group_name(curve)), 0),
         OSSL_PARAM_construct_end()};
    if (EVP_PKEY_CTX_set_params(ctx.get(), params) <= 0) return std::nullopt;

    EVP_PKEY* raw_pkey = nullptr;
    if (EVP_PKEY_generate(ctx.get(), &raw_pkey) <= 0) return std::nullopt;
    EvpPkeyPtr pkey(raw_pkey);

    BIGNUM* bn_priv = nullptr;
    if (!EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv)) return std::nullopt;
    BnPtr priv_guard(bn_priv);

    auto slen = scalar_len(curve);
    std::vector<uint8_t> priv_bytes(slen);
    BN_bn2binpad(bn_priv, priv_bytes.data(), static_cast<int>(slen));

    size_t pub_len = 0;
    if (!EVP_PKEY_get_octet_string_param(pkey.get(), OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pub_len))
        return std::nullopt;

    std::vector<uint8_t> pub_bytes(pub_len);
    if (!EVP_PKEY_get_octet_string_param(pkey.get(), OSSL_PKEY_PARAM_PUB_KEY, pub_bytes.data(),
                                         pub_bytes.size(), &pub_len))
        return std::nullopt;
    pub_bytes.resize(pub_len);

    auto pub_sb = StaticBytes<kP384PublicKeyLen>::from(pub_bytes);
    auto priv_sb = StaticBytes<kP384ScalarLen>::from(priv_bytes);
    if (!pub_sb || !priv_sb) return std::nullopt;
    return KeyPair{*pub_sb, *priv_sb};
}

// ============ ECDSA ============

std::optional<Signature> ecdsa_sign(const std::vector<uint8_t>& private_key,
                                    const std::vector<uint8_t>& message) {

    auto pkey = evp_pkey_from_private(private_key, Curve::NistP256);
    if (!pkey) return std::nullopt;

    EvpMdCtxPtr md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) return std::nullopt;

    if (EVP_DigestSignInit(md_ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) <= 0)
        return std::nullopt;

    if (EVP_DigestSignUpdate(md_ctx.get(), message.data(), message.size()) <= 0)
        return std::nullopt;

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(md_ctx.get(), nullptr, &sig_len) <= 0) return std::nullopt;

    std::vector<uint8_t> der_sig(sig_len);
    if (EVP_DigestSignFinal(md_ctx.get(), der_sig.data(), &sig_len) <= 0) return std::nullopt;
    der_sig.resize(sig_len);

    Signature result;
    if (!extract_rs_from_der(der_sig.data(), der_sig.size(), result, kP256ScalarLen))
        return std::nullopt;

    return result;
}

std::optional<Signature> ecdsa_sign_digest(const std::vector<uint8_t>& private_key,
                                           const std::vector<uint8_t>& digest) {
    return ecdsa_sign_digest(private_key, digest, Curve::NistP256);
}

std::optional<Signature> ecdsa_sign_digest(const std::vector<uint8_t>& private_key,
                                           const std::vector<uint8_t>& digest, Curve curve) {

    auto slen = scalar_len(curve);
    auto hlen = hash_len(curve);
    if (digest.size() != hlen) return std::nullopt;

    auto pkey = evp_pkey_from_private(private_key, curve);
    if (!pkey) return std::nullopt;

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
    if (!ctx) return std::nullopt;

    if (EVP_PKEY_sign_init(ctx.get()) <= 0) return std::nullopt;

    size_t sig_len = 0;
    if (EVP_PKEY_sign(ctx.get(), nullptr, &sig_len, digest.data(), digest.size()) <= 0)
        return std::nullopt;

    std::vector<uint8_t> der_sig(sig_len);
    if (EVP_PKEY_sign(ctx.get(), der_sig.data(), &sig_len, digest.data(), digest.size()) <= 0)
        return std::nullopt;
    der_sig.resize(sig_len);

    Signature result;
    if (!extract_rs_from_der(der_sig.data(), der_sig.size(), result, slen)) return std::nullopt;

    return result;
}

bool ecdsa_verify(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& message,
                  const Signature& sig) {

    auto pkey = evp_pkey_from_public(public_key, Curve::NistP256);
    if (!pkey) return false;

    auto der_sig = build_der_from_rs(sig.r.data(), sig.r.size(), sig.s.data(), sig.s.size());

    EvpMdCtxPtr md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) return false;

    if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) <= 0)
        return false;

    if (EVP_DigestVerifyUpdate(md_ctx.get(), message.data(), message.size()) <= 0) return false;

    return EVP_DigestVerifyFinal(md_ctx.get(), der_sig.data(), der_sig.size()) == 1;
}

bool ecdsa_verify_digest(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& digest,
                         const Signature& sig) {
    return ecdsa_verify_digest(public_key, digest, sig, Curve::NistP256);
}

bool ecdsa_verify_digest(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& digest,
                         const Signature& sig, Curve curve) {

    if (digest.size() != hash_len(curve)) return false;

    auto pkey = evp_pkey_from_public(public_key, curve);
    if (!pkey) return false;

    auto der_sig = build_der_from_rs(sig.r.data(), sig.r.size(), sig.s.data(), sig.s.size());

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
    if (!ctx) return false;

    if (EVP_PKEY_verify_init(ctx.get()) <= 0) return false;

    return EVP_PKEY_verify(ctx.get(), der_sig.data(), der_sig.size(), digest.data(),
                           digest.size()) == 1;
}

// ============ ECDH ============

std::optional<std::vector<uint8_t>> ecdh_derive(const std::vector<uint8_t>& private_key,
                                                const std::vector<uint8_t>& peer_public_key) {
    return ecdh_derive(private_key, peer_public_key, Curve::NistP256);
}

std::optional<std::vector<uint8_t>> ecdh_derive(const std::vector<uint8_t>& private_key,
                                                const std::vector<uint8_t>& peer_public_key,
                                                Curve curve) {

    auto priv_pkey = evp_pkey_from_private(private_key, curve);
    auto pub_pkey = evp_pkey_from_public(peer_public_key, curve);
    if (!priv_pkey || !pub_pkey) return std::nullopt;

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(priv_pkey.get(), nullptr));
    if (!ctx) return std::nullopt;

    if (EVP_PKEY_derive_init(ctx.get()) <= 0) return std::nullopt;
    if (EVP_PKEY_derive_set_peer(ctx.get(), pub_pkey.get()) <= 0) return std::nullopt;

    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) <= 0) return std::nullopt;

    std::vector<uint8_t> secret(secret_len);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &secret_len) <= 0) return std::nullopt;
    secret.resize(secret_len);

    return secret;
}

// ============ Hashing ============

std::vector<uint8_t> hash_sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> digest(kSha256Len);
    unsigned int len = 0;
    EVP_Digest(data.data(), data.size(), digest.data(), &len, EVP_sha256(), nullptr);
    digest.resize(len);
    return digest;
}

std::vector<uint8_t> hash_sha384(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> digest(kSha384Len);
    unsigned int len = 0;
    EVP_Digest(data.data(), data.size(), digest.data(), &len, EVP_sha384(), nullptr);
    digest.resize(len);
    return digest;
}

std::vector<uint8_t> hash_for_curve(const std::vector<uint8_t>& data, Curve curve) {
    switch (curve) {
        case Curve::NistP256:
        case Curve::BrainpoolP256r1: return hash_sha256(data);
        case Curve::NistP384:
        case Curve::BrainpoolP384r1: return hash_sha384(data);
    }
    return hash_sha256(data);
}

} // namespace v2xpki::crypto
