// Atomic file writes and PEM SEC1 key output.

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace provisioning {

bool atomic_write(const std::string &path, const std::vector<uint8_t> &data);
bool atomic_write_key_pem(const std::string &path, const std::vector<uint8_t> &private_key);

std::string hex8(const std::array<uint8_t, 8> &a);

} // namespace provisioning
