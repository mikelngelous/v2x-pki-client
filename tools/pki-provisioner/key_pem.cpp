// Atomic file writes and PEM SEC1 key output.

#include "key_pem.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>

#include "v2xpki/sizes.hpp"

namespace provisioning {

bool atomic_write(const std::string &path, const std::vector<uint8_t> &data) {
    std::string tmp = path + ".tmp";
    FILE *f = fopen(tmp.c_str(), "wb");
    if (!f) {
        fprintf(stderr, "[pki-provisioner] ERROR: cannot open %s: %s\n", tmp.c_str(), strerror(errno));
        return false;
    }
    if (fwrite(data.data(), 1, data.size(), f) != data.size()) {
        fprintf(stderr, "[pki-provisioner] ERROR: write failed %s\n", tmp.c_str());
        fclose(f);
        unlink(tmp.c_str());
        return false;
    }
    fclose(f);
    if (rename(tmp.c_str(), path.c_str()) != 0) {
        fprintf(stderr, "[pki-provisioner] ERROR: rename %s -> %s: %s\n", tmp.c_str(), path.c_str(),
                strerror(errno));
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

bool atomic_write_key_pem(const std::string &path, const std::vector<uint8_t> &private_key) {
    BIGNUM *bn_priv = BN_bin2bn(private_key.data(), static_cast<int>(private_key.size()), nullptr);
    if (!bn_priv) {
        fprintf(stderr, "[pki-provisioner] ERROR: BN_bin2bn failed\n");
        return false;
    }

    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *pub = EC_POINT_new(grp);
    BN_CTX *bnctx = BN_CTX_new();
    bool point_ok = grp && pub && bnctx &&
                    EC_POINT_mul(grp, pub, bn_priv, nullptr, nullptr, bnctx) == 1;
    std::vector<uint8_t> pub_buf;
    if (point_ok) {
        size_t pub_len = EC_POINT_point2oct(grp, pub, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0,
                                            bnctx);
        pub_buf.resize(pub_len);
        EC_POINT_point2oct(grp, pub, POINT_CONVERSION_UNCOMPRESSED, pub_buf.data(), pub_len, bnctx);
    }
    if (bnctx) BN_CTX_free(bnctx);
    if (pub) EC_POINT_free(pub);
    if (grp) EC_GROUP_free(grp);

    if (!point_ok || pub_buf.empty()) {
        fprintf(stderr, "[pki-provisioner] ERROR: public point derivation failed\n");
        BN_free(bn_priv);
        return false;
    }

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bn_priv);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_buf.data(), pub_buf.size());
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    BN_free(bn_priv);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY *pkey = nullptr;
    bool key_ok = pctx && EVP_PKEY_fromdata_init(pctx) > 0 &&
                  EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) > 0;
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(pctx);

    if (!key_ok || !pkey) {
        fprintf(stderr, "[pki-provisioner] ERROR: EVP_PKEY_fromdata failed\n");
        if (pkey) EVP_PKEY_free(pkey);
        return false;
    }

    // SEC1 PEM: -----BEGIN EC PRIVATE KEY-----
    BIO *bio = BIO_new(BIO_s_mem());
    OSSL_ENCODER_CTX
        *ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey,
                                              OSSL_KEYMGMT_SELECT_KEYPAIR |
                                                  OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                                              "PEM", "EC", nullptr);
    bool enc_ok = bio && ectx && OSSL_ENCODER_to_bio(ectx, bio) == 1;
    OSSL_ENCODER_CTX_free(ectx);
    EVP_PKEY_free(pkey);

    if (!enc_ok) {
        fprintf(stderr, "[pki-provisioner] ERROR: OSSL_ENCODER_to_bio failed\n");
        if (bio) BIO_free(bio);
        return false;
    }

    char *pem_data = nullptr;
    long pem_len = BIO_get_mem_data(bio, &pem_data);
    std::vector<uint8_t> pem_bytes(pem_data, pem_data + pem_len);
    BIO_free(bio);

    return atomic_write(path, pem_bytes);
}

std::string hex8(const std::array<uint8_t, 8> &a) {
    char buf[17];
    for (int i = 0; i < 8; i++)
        snprintf(buf + i * 2, 3, "%02X", a[i]);
    return buf;
}

} // namespace provisioning
