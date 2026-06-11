// COER/UPER encode-decode + OCTET_STRING helpers.

#include "coer.hpp"

#include <cstdlib>

namespace v2xpki::coer {

std::vector<uint8_t> encode(const asn_TYPE_descriptor_t *td, const void *sptr) {
    auto res = asn_encode_to_new_buffer(nullptr, ATS_CANONICAL_OER, td, sptr);
    if (!res.buffer || res.result.encoded < 0) {
        free(res.buffer);
        return {};
    }
    auto *buf = static_cast<uint8_t *>(res.buffer);
    std::vector<uint8_t> result(buf, buf + res.result.encoded);
    free(res.buffer);
    return result;
}

void *decode(const asn_TYPE_descriptor_t *td, const uint8_t *buf, size_t len) {
    void *structure = nullptr;
    asn_dec_rval_t dr = asn_decode(nullptr, ATS_CANONICAL_OER, td, &structure, buf, len);
    if (dr.code != RC_OK) {
        if (structure) ASN_STRUCT_FREE(*td, structure);
        return nullptr;
    }
    return structure;
}

void *decode_with_basic_fallback(const asn_TYPE_descriptor_t *td, const uint8_t *buf, size_t len) {
    void *structure = nullptr;
    asn_dec_rval_t dr = asn_decode(nullptr, ATS_CANONICAL_OER, td, &structure, buf, len);
    if (dr.code == RC_OK) return structure;

    if (structure) {
        ASN_STRUCT_FREE(*td, structure);
        structure = nullptr;
    }

    dr = asn_decode(nullptr, ATS_BASIC_OER, td, &structure, buf, len);
    if (dr.code != RC_OK) {
        if (structure) ASN_STRUCT_FREE(*td, structure);
        return nullptr;
    }
    return structure;
}

std::vector<uint8_t> encode_uper(const asn_TYPE_descriptor_t *td, const void *sptr) {
    void *buffer = nullptr;
    ssize_t nbytes = uper_encode_to_new_buffer(td, nullptr, sptr, &buffer);
    if (nbytes < 0 || buffer == nullptr) {
        free(buffer);
        return {};
    }
    auto *buf = static_cast<uint8_t *>(buffer);
    std::vector<uint8_t> result(buf, buf + nbytes);
    free(buffer);
    return result;
}

void *decode_uper(const asn_TYPE_descriptor_t *td, const uint8_t *buf, size_t len) {
    void *structure = nullptr;
    asn_dec_rval_t dr = uper_decode_complete(nullptr, td, &structure, buf, len);
    if (dr.code != RC_OK) {
        if (structure) ASN_STRUCT_FREE(*td, structure);
        return nullptr;
    }
    return structure;
}

} // namespace v2xpki::coer

namespace v2xpki::octet {

void set(OCTET_STRING_t *os, const uint8_t *data, size_t len) {
    OCTET_STRING_fromBuf(os, reinterpret_cast<const char *>(data), static_cast<int>(len));
}

std::vector<uint8_t> bytes(const OCTET_STRING_t *os) {
    if (!os || !os->buf || os->size == 0) return {};
    return {os->buf, os->buf + os->size};
}

} // namespace v2xpki::octet
