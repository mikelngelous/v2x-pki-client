// CLI argument parsing.

#include "args.hpp"

#include <cstring>
#include <iomanip>
#include <iostream>

namespace v2xpki::cli {

Args parse_args(int argc, char **argv) {
    Args a;
    if (argc < 2) return a;
    a.command = argv[1];
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--json") {
            a.json = true;
            continue;
        }
        if (arg == "--discover") {
            a.discover_mode = true;
            continue;
        }
        if (i + 1 >= argc) continue;
        std::string val = argv[i + 1];
        if (arg == "--pki-url") {
            a.pki_url = val;
            ++i;
        } else if (arg == "--out-dir") {
            a.out_dir = val;
            ++i;
        } else if (arg == "--hid8") {
            a.hid8 = val;
            ++i;
        } else if (arg == "--cert-path") {
            a.cert_path = val;
            ++i;
        } else if (arg == "--ea-url") {
            a.ea_url = val;
            ++i;
        } else if (arg == "--aa-url") {
            a.aa_url = val;
            ++i;
        } else if (arg == "--keystore-dir") {
            a.keystore_dir = val;
            ++i;
        } else if (arg == "--ec-cert") {
            a.ec_cert = val;
            ++i;
        } else if (arg == "--tlm-cert") {
            a.tlm_cert = val;
            ++i;
        } else if (arg == "--tlm-hid8") {
            a.tlm_hid8 = val;
            ++i;
        } else if (arg == "--out") {
            a.out = val;
            ++i;
        } else if (arg == "--canonical-key") {
            a.canonical_key = val;
            ++i;
        } else if (arg == "--canonical-id") {
            a.canonical_id = val;
            a.canonical_id_set = true;
            ++i;
        } else if (arg == "--curve") {
            a.curve_str = val;
            ++i;
        }
    }
    return a;
}

Curve parse_curve(const std::string &s) {
    if (s == "brainpool-p256r1" || s == "brainpoolP256r1") return Curve::BrainpoolP256r1;
    if (s == "brainpool-p384r1" || s == "brainpoolP384r1") return Curve::BrainpoolP384r1;
    return Curve::NistP256;
}

void usage(const char *prog, const Command *cmds, size_t count) {
    std::cerr << "Usage: " << prog << " <command> [options]\n\nCommands:\n";
    for (size_t i = 0; i < count; ++i)
        std::cerr << "  " << std::left << std::setw(15) << cmds[i].name << cmds[i].help << "\n";
    std::cerr
        << "\nCommon options:\n"
        << "  --pki-url URL        Base URL of PKI server\n"
        << "  --json               Machine-readable JSON output\n"
        << "  --out-dir DIR        Output directory for certs\n"
        << "  --hid8 HEX           HashedId8 in hex (16 chars)\n"
        << "  --tlm-hid8 HEX       Pinned TLM HashedId8 (hex uppercase)\n"
        << "  --cert-path PATH     Path to cert file (COER)\n"
        << "  --ea-url URL         EA POST endpoint\n"
        << "  --aa-url URL         AA POST endpoint\n"
        << "  --keystore-dir DIR   Key storage directory\n"
        << "  --tlm-cert PATH      TLM cert for ECTL verification\n"
        << "  --out PATH           Output file path\n"
        << "  --canonical-key ID   Key handle ID for canonical key\n"
        << "  --canonical-id STR   ITS-S canonical identifier (1-64 bytes, default: v2xpki-its-s)\n"
        << "  --ec-cert PATH       EC cert file for AT request\n"
        << "  --curve NAME         Curve: nist-p256, brainpool-p256r1, brainpool-p384r1\n"
        << "  --discover           Use CCMS discovery for EA/AA URLs\n";
}

} // namespace v2xpki::cli
