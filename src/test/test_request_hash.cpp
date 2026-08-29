// Tests for the requestHash correlation check (TS 102 941 §6.2.3.2.2 / §6.2.3.3.2).

#include <gtest/gtest.h>

#include "internal/request_hash.hpp"

#include <string>

using namespace v2xpki;

namespace {

std::vector<uint8_t> bytes_of(const std::string& s) { return {s.begin(), s.end()}; }

StaticBytes<16> leftmost16(const std::vector<uint8_t>& request_bytes) {
    auto digest = crypto::hash_sha256(request_bytes);
    return *StaticBytes<16>::from(digest.data(), 16);
}

} // namespace

TEST(RequestHashTest, AcceptsLeftmost16OfSha256) {
    auto request = bytes_of("the exact bytes we POSTed");
    EXPECT_TRUE(request_hash_matches(request, leftmost16(request)));
}

// Known-answer test: pins the rule to leftmost-16-of-SHA-256, not some other digest or slice.
// SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
TEST(RequestHashTest, KnownAnswer) {
    std::vector<uint8_t> expected = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                                     0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23};
    auto hash = *StaticBytes<16>::from(expected);
    EXPECT_TRUE(request_hash_matches(bytes_of("abc"), hash));
}

TEST(RequestHashTest, RejectsFlippedByte) {
    auto request = bytes_of("the exact bytes we POSTed");
    auto digest = crypto::hash_sha256(request);
    digest[0] ^= 0xFF;
    EXPECT_FALSE(request_hash_matches(request, *StaticBytes<16>::from(digest.data(), 16)));
}

// The response is correlated to a different request — the case this check exists to catch.
TEST(RequestHashTest, RejectsHashOfDifferentRequest) {
    auto request = bytes_of("request A");
    auto other = bytes_of("request B");
    EXPECT_FALSE(request_hash_matches(request, leftmost16(other)));
}

// Fail-closed: no request bytes means the check cannot be performed, so it must not pass.
TEST(RequestHashTest, RejectsEmptyRequest) {
    EXPECT_FALSE(request_hash_matches({}, leftmost16(bytes_of("anything"))));
}

TEST(RequestHashTest, RejectsShortHash) {
    auto request = bytes_of("the exact bytes we POSTed");
    auto digest = crypto::hash_sha256(request);
    EXPECT_FALSE(request_hash_matches(request, *StaticBytes<16>::from(digest.data(), 15)));
}
