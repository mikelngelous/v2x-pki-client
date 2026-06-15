#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace v2xpki::cli {

std::string bytes_to_hex(const uint8_t *data, size_t len);
std::string hid8_hex(const std::array<uint8_t, 8> &h);
std::array<uint8_t, 8> hex_to_hid8(const std::string &hex);
std::string body_to_string(const std::vector<uint8_t> &body);
std::vector<uint8_t> read_file(const std::string &path);
bool write_file(const std::string &path, const std::vector<uint8_t> &data);
std::array<uint8_t, 8> compute_hid8(const std::vector<uint8_t> &cert_coer);

struct CertSummary {
    std::array<uint8_t, 8> hid8{};
    std::array<uint8_t, 8> issuer_hid8{};
    bool self_signed = false;
    std::vector<int64_t> psids;
    size_t size_bytes = 0;
    bool valid = false;
};

CertSummary parse_cert_summary(const std::vector<uint8_t> &coer);
void print_cert_summary(const CertSummary &s, bool json);

} // namespace v2xpki::cli
