#pragma once

#include "v2xpki/sizes.hpp"

#include <string>

namespace v2xpki::cli {

struct Args {
    std::string command;
    std::string pki_url;
    std::string out_dir;
    std::string hid8;
    std::string cert_path;
    std::string ea_url;
    std::string aa_url;
    std::string keystore_dir;
    std::string ec_cert;
    std::string tlm_cert;
    std::string tlm_hid8;
    std::string out;
    std::string canonical_key;
    std::string canonical_id;
    bool canonical_id_set = false;
    std::string curve_str;
    bool json = false;
    bool discover_mode = false;
};

struct Command {
    const char *name;
    int (*handler)(const Args &);
    const char *help;
};

Args parse_args(int argc, char **argv);
Curve parse_curve(const std::string &s);
void usage(const char *prog, const Command *cmds, size_t count);

} // namespace v2xpki::cli
