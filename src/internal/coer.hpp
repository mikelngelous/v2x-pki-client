// COER/UPER encode-decode + OCTET_STRING helpers.

#pragma once

#include <cstdint>
#include <vector>

extern "C" {
#include "OCTET_STRING.h"
#include "asn_application.h"
}

namespace v2xpki::coer {

std::vector<uint8_t> encode(const asn_TYPE_descriptor_t *td, const void *sptr);

void *decode(const asn_TYPE_descriptor_t *td, const uint8_t *buf, size_t len);

// Required for trust_list: some ECTL producers emit non-canonical OER.
void *decode_with_basic_fallback(const asn_TYPE_descriptor_t *td, const uint8_t *buf, size_t len);

std::vector<uint8_t> encode_uper(const asn_TYPE_descriptor_t *td, const void *sptr);

void *decode_uper(const asn_TYPE_descriptor_t *td, const uint8_t *buf, size_t len);

} // namespace v2xpki::coer

namespace v2xpki::octet {

void set(OCTET_STRING_t *os, const uint8_t *data, size_t len);

std::vector<uint8_t> bytes(const OCTET_STRING_t *os);

} // namespace v2xpki::octet
