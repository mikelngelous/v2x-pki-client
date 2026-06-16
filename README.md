# v2x-pki-client

A standalone ETSI C-ITS PKI client: TS 102 941 enrolment/authorization,
IEEE 1609.2 signatures, COER wire.

NIST P-256 today; Brainpool P-256r1/P-384r1 on the roadmap. The bundled
`PlaintextFileKeyStore` is DEV ONLY (PKCS#11 is a roadmap target).

## Build

```bash
git submodule update --init --recursive
./scripts/regen-codecs.sh        # generate ASN.1 codecs into generated/
cmake -B build && cmake --build build -j
```

## CLI

`v2x-pki-client <command>`:

| Command | What it does |
|---|---|
| `healthz` / `version` / `info` | Endpoint liveness and metadata |
| `discover` | CCMS trust discovery (TLM → ECTL → CTL) |
| `fetch-trust` | Fetch RCA / TLM / cert chain |
| `lookup-cert` | Resolve a certificate by name or HashedId8 |
| `fetch-ectl` | Fetch the European Certificate Trust List |
| `verify-hid8` | Verify HashedId8 against a cached cert |
| `enrol` | Enrolment Credential (EC) request |
| `request-at` | Authorization Ticket (AT) request |

`pki-provisioner` fetches trust, enrols an EC and rotates ATs to disk for V2X
stacks that consume per-station credentials as files.

## Library

Four static libraries, namespace `v2xpki::`, linkable from CMake:

- `v2xpki-codecs` — ASN.1 codecs (IEEE 1609.2 + TS 102 941)
- `v2xpki-crypto` — ECDSA, ECIES, key storage
- `v2xpki-transport` — HTTP client + trust chain validation
- `v2xpki-facade` — high-level enrolment/authorization API

## Dependencies

- OpenSSL ≥ 3.0.13
- libcurl ≥ 7.80
- CMake ≥ 3.16
- C++17 compiler

## License

Apache-2.0. Maintained by Miguel Fornell.
