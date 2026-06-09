#!/usr/bin/env bash
# Build, test, and install v2xpki as an exportable CMake package under dist/.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build-release"
DELIVERABLE="${REPO_ROOT}/dist/v2xpki-package"

echo "=== v2xpki package builder ==="
echo "Source: ${REPO_ROOT}"
echo "Output: ${DELIVERABLE}"

# 1. Configure (Release)
echo ""
echo "[1/5] Configuring (Release)..."
cmake -B "${BUILD_DIR}" -S "${REPO_ROOT}" -DCMAKE_BUILD_TYPE=Release

# 2. Build
echo ""
echo "[2/5] Building..."
cmake --build "${BUILD_DIR}" -j"$(nproc)"

# 3. Test
echo ""
echo "[3/5] Running tests..."
(cd "${BUILD_DIR}" && ctest --output-on-failure)

# 4. Install to deliverable prefix
echo ""
echo "[4/5] Installing to ${DELIVERABLE}..."
rm -rf "${DELIVERABLE}"
cmake --install "${BUILD_DIR}" --prefix "${DELIVERABLE}"

# 5. Copy examples and docs
echo ""
echo "[5/5] Copying examples and docs..."
cp -r "${REPO_ROOT}/examples" "${DELIVERABLE}/examples"
cp -r "${REPO_ROOT}/docs"     "${DELIVERABLE}/docs"

echo ""
echo "=== Package complete ==="
echo ""
echo "Layout:"
find "${DELIVERABLE}" -type f | sort | sed "s|${DELIVERABLE}/|  |"
echo ""
echo "Consumer usage:"
echo "  cmake -B build -DCMAKE_PREFIX_PATH=${DELIVERABLE}"
echo "  # In CMakeLists.txt: find_package(v2xpki REQUIRED)"
echo "  # target_link_libraries(app PRIVATE v2xpki::facade)"
