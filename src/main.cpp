// v2x-pki-client CLI.

#include "cli/args.hpp"
#include "cli/commands.hpp"

#include <cstring>
#include <iostream>

using v2xpki::cli::Args;
using v2xpki::cli::Command;

static const Command kCommands[] = {
    {"healthz", v2xpki::cli::cmd_healthz, "GET /healthz from PKI server"},
    {"version", v2xpki::cli::cmd_version, "GET /version from PKI server"},
    {"info", v2xpki::cli::cmd_info, "Show client binary info"},
    {"discover", v2xpki::cli::cmd_discover, "CCMS trust discovery (ECTL + CTL)"},
    {"fetch-trust", v2xpki::cli::cmd_fetch_trust, "Download trust material (RCA, TLM, MA certs)"},
    {"lookup-cert", v2xpki::cli::cmd_lookup_cert, "Lookup cert by HashedId8"},
    {"fetch-ectl", v2xpki::cli::cmd_fetch_ectl, "Download and verify ECTL"},
    {"verify-hid8", v2xpki::cli::cmd_verify_hid8,
     "Compute HashedId8 of a local cert file (--hid8 pins expected)"},
    {"enrol", v2xpki::cli::cmd_enrol, "Request Enrolment Credential from EA"},
    {"request-at", v2xpki::cli::cmd_request_at, "Request Authorization Ticket from AA"},
};

int main(int argc, char **argv) {
    if (argc < 2) {
        v2xpki::cli::usage(argv[0], kCommands, std::size(kCommands));
        return 1;
    }

    auto args = v2xpki::cli::parse_args(argc, argv);

    for (const auto &cmd : kCommands) {
        if (args.command == cmd.name) return cmd.handler(args);
    }

    std::cerr << "error: unknown command '" << args.command << "'\n";
    v2xpki::cli::usage(argv[0], kCommands, std::size(kCommands));
    return 1;
}
