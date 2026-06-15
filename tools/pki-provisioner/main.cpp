// V2X credential provisioner. Produces AT.coer + AT.key + AA.coer + RCA.coer for V2X stacks
// consuming per-station credentials.

#include "pki-provisioner/flow.hpp"

#include "v2xpki/http_client.hpp"

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <vector>

using namespace v2xpki;

static volatile sig_atomic_t g_running = 1;

static void signal_handler(int) { g_running = 0; }

struct Config {
    std::string pki_base_url = "https://pki.skyv2x.com";
    std::string tlm_hid8; // empty -> bootstrap TLM via /tlm shortcut
    std::string output_dir = "./v3-certs";
    int64_t validity_period_hours = 168;
    double rotation_ratio = 0.8;
    std::vector<int64_t> psids = {36, 37, 137, 138, 139, 140};
    int64_t ec_validity_days = 30;
    bool oneshot = false;
};

static std::string env_or(const char *name, const std::string &def) {
    const char *v = getenv(name);
    return v ? v : def;
}

static Config parse_config(int argc, char *argv[]) {
    Config cfg;
    cfg.pki_base_url = env_or("PKI_BASE_URL", cfg.pki_base_url);
    cfg.tlm_hid8 = env_or("TLM_HID8", cfg.tlm_hid8);
    cfg.output_dir = env_or("AT_OUTPUT_DIR", cfg.output_dir);

    const char *vh = getenv("AT_VALIDITY_HOURS");
    if (vh) cfg.validity_period_hours = std::atol(vh);

    const char *rr = getenv("AT_ROTATION_RATIO");
    if (rr) cfg.rotation_ratio = std::atof(rr);

    const char *ed = getenv("EC_VALIDITY_DAYS");
    if (ed) cfg.ec_validity_days = std::atol(ed);

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if ((arg == "--url" || arg == "-u") && i + 1 < argc)
            cfg.pki_base_url = argv[++i];
        else if (arg == "--tlm-hid8" && i + 1 < argc)
            cfg.tlm_hid8 = argv[++i];
        else if ((arg == "--output" || arg == "-o") && i + 1 < argc)
            cfg.output_dir = argv[++i];
        else if (arg == "--validity-hours" && i + 1 < argc)
            cfg.validity_period_hours = std::atol(argv[++i]);
        else if (arg == "--rotation-ratio" && i + 1 < argc)
            cfg.rotation_ratio = std::atof(argv[++i]);
        else if (arg == "--oneshot")
            cfg.oneshot = true;
        else if (arg == "--help" || arg == "-h") {
            printf("Usage: pki-provisioner [OPTIONS]\n\n"
                   "Options:\n"
                   "  -u, --url URL           PKI base URL (default: https://pki.skyv2x.com)\n"
                   "  --tlm-hid8 HEX          Pinned TLM HashedId8 (conformant anchor; without\n"
                   "                          it the TLM is bootstrapped via the /tlm shortcut)\n"
                   "  -o, --output DIR        Output directory (default: ./v3-certs)\n"
                   "  --validity-hours N      AT validity period in hours (default: 168)\n"
                   "  --rotation-ratio R      Rotate at R*validity (default: 0.8)\n"
                   "  --oneshot               Single rotation then exit\n"
                   "  -h, --help              Show this help\n\n"
                   "Environment variables:\n"
                   "  PKI_BASE_URL, TLM_HID8, AT_OUTPUT_DIR, AT_VALIDITY_HOURS,\n"
                   "  AT_ROTATION_RATIO, EC_VALIDITY_DAYS\n");
            exit(0);
        }
    }

    return cfg;
}

static void sleep_interruptible(long seconds) {
    for (long i = 0; i < seconds && g_running; i++)
        std::this_thread::sleep_for(std::chrono::seconds(1));
}

int main(int argc, char *argv[]) {
    Config cfg = parse_config(argc, argv);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("[pki-provisioner] pki-provisioner starting\n");
    printf("[pki-provisioner] PKI URL:          %s\n", cfg.pki_base_url.c_str());
    printf("[pki-provisioner] TLM HID8:         %s\n",
           cfg.tlm_hid8.empty() ? "(bootstrap via /tlm)" : cfg.tlm_hid8.c_str());
    printf("[pki-provisioner] Output dir:       %s\n", cfg.output_dir.c_str());
    printf("[pki-provisioner] Validity:         %ldh\n", (long)cfg.validity_period_hours);
    printf("[pki-provisioner] Rotation ratio:   %.2f\n", cfg.rotation_ratio);
    printf("[pki-provisioner] Mode:             %s\n", cfg.oneshot ? "oneshot" : "continuous");

    mkdir(cfg.output_dir.c_str(), 0755);

    printf("\n[pki-provisioner] === Trust discovery ===\n");
    auto anchors = provisioning::discover(cfg.pki_base_url, cfg.tlm_hid8, cfg.output_dir);
    if (!anchors) return 1;
    if (!provisioning::write_anchors(*anchors, cfg.output_dir)) return 1;

    HttpClient http(HttpClientConfig{"", std::chrono::seconds{30}, true});

    printf("\n[pki-provisioner] === EC Enrollment ===\n");
    auto ec = provisioning::enrol_ec(http, *anchors, cfg.psids, cfg.ec_validity_days);
    if (!ec) return 1;

    int rotation_count = 0;
    while (g_running) {
        rotation_count++;
        printf("\n[pki-provisioner] === AT Rotation #%d ===\n", rotation_count);

        auto hid8 = provisioning::rotate_at(http, *anchors, *ec, cfg.psids,
                                            cfg.validity_period_hours, cfg.output_dir);
        if (!hid8) {
            if (cfg.oneshot) return 1;
            fprintf(stderr, "[pki-provisioner] rotation failed, retrying in 60s\n");
            sleep_interruptible(60);
            continue;
        }

        if (cfg.oneshot) {
            printf("\n[pki-provisioner] Oneshot mode — exiting.\n");
            break;
        }

        double sleep_hours = cfg.validity_period_hours * cfg.rotation_ratio;
        printf("[pki-provisioner] Next rotation in %.1fh [%.0f%% of %ldh validity]\n", sleep_hours,
               cfg.rotation_ratio * 100, (long)cfg.validity_period_hours);
        sleep_interruptible(static_cast<long>(sleep_hours * 3600.0));
    }

    if (!g_running) printf("\n[pki-provisioner] Caught signal, shutting down.\n");

    printf("[pki-provisioner] Total rotations: %d\n", rotation_count);
    return 0;
}
