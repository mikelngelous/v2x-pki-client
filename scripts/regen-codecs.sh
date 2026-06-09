#!/bin/bash
# Regenerate C codecs from ASN.1 schemas with asn1c Mouse v1.4.2.
# Run from the repo root.
set -euo pipefail

SUBMOD="third_party/asn1c-mouse"
ASN1C_BIN="${ASN1C:-$SUBMOD/asn1c/asn1c}"
# Pin runtime skeletons to the submodule fork. Without -S, asn1c copies them
# from its compiled-in SKELETONS_DIR (typically /usr/local/share/asn1c), which
# may belong to a different asn1c build and emit codecs that fail to compile.
SKEL_DIR="$SUBMOD/skeletons"
OUTDIR="generated"

# Ensure the submodule is initialised.
if [ ! -f "$SUBMOD/configure.ac" ]; then
    git submodule update --init --recursive
fi

# Build asn1c if the binary is not present in the submodule.
if [ ! -x "$ASN1C_BIN" ]; then
    echo "Building asn1c in $SUBMOD ..."
    (cd "$SUBMOD" && autoreconf -iv && ./configure && make -j)
fi

if ! "$ASN1C_BIN" -version &>/dev/null; then
    echo "ERROR: asn1c at $ASN1C_BIN is not executable" >&2
    exit 1
fi

echo "Cleaning $OUTDIR/ ..."
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

echo "Generating codecs with: $("$ASN1C_BIN" -version 2>&1 | head -1)"
"$ASN1C_BIN" -S "$SKEL_DIR" -fcompound-names -gen-UPER -gen-OER \
    -no-gen-BER -no-gen-XER -no-gen-JER -no-gen-example \
    -pdu=EtsiTs102941Data \
    -pdu=EtsiTs103097Certificate \
    -pdu=Ieee1609Dot2Data \
    -D "$OUTDIR/" \
    asn/*.asn 2>&1 | grep -v "^WARNING" || true

rm -f "$OUTDIR/Makefile.am.libasncodec" asn_constant.h
echo "Generated: $(ls "$OUTDIR"/*.c | wc -l) .c files"
