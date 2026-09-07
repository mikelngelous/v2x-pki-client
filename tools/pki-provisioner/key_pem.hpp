// Atomic file writes and PEM SEC1 key output.

#pragma once

#include <array>
#include <cstdint>
#include "v2xpki/sizes.hpp"

#include <string>
#include <vector>

namespace provisioning {

bool atomic_write(const std::string &path, const std::vector<uint8_t> &data);
// curve must match the key: a P-256 group with a Brainpool scalar silently yields a wrong key.
bool atomic_write_key_pem(const std::string &path, const std::vector<uint8_t> &private_key,
                          v2xpki::Curve curve);

std::string hex8(const std::array<uint8_t, 8> &a);

} // namespace provisioning
