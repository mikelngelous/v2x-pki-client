#pragma once

#include "args.hpp"

namespace v2xpki::cli {

int cmd_healthz(const Args &a);
int cmd_version(const Args &a);
int cmd_info(const Args &a);
int cmd_discover(const Args &a);
int cmd_fetch_trust(const Args &a);
int cmd_lookup_cert(const Args &a);
int cmd_fetch_ectl(const Args &a);
int cmd_verify_hid8(const Args &a);
int cmd_enrol(const Args &a);
int cmd_request_at(const Args &a);

} // namespace v2xpki::cli
