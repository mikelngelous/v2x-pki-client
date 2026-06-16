# v2x-pki-client — ETSI C-ITS PKI client.

cmake_minimum_required(VERSION 3.16)
project(v2xpki VERSION 0.1.0 LANGUAGES C CXX)

find_package(OpenSSL REQUIRED)
if(OPENSSL_VERSION VERSION_LESS 3.0.13)
    message(FATAL_ERROR
        "OpenSSL ${OPENSSL_VERSION}: 3.0.2-series EVP_PKEY regression breaks ECDSA/ECIES. "
        "Require >= 3.0.13 — pass -DOPENSSL_ROOT_DIR=/path/to/openssl-3.5.x.")
endif()
find_package(CURL REQUIRED)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

configure_file(
    include/v2xpki/version.hpp.in
    include/v2xpki/version.hpp
    @ONLY
)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(V2XPKI_BUILD_TESTS_DEFAULT ON)
else()
    set(V2XPKI_BUILD_TESTS_DEFAULT OFF)
endif()
option(V2XPKI_BUILD_TESTS "Build v2xpki tests" ${V2XPKI_BUILD_TESTS_DEFAULT})

if(V2XPKI_BUILD_TESTS)
    enable_testing()
    include(FetchContent)
    FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.15.2)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

add_subdirectory(src)
add_subdirectory(tools)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS
    v2xpki-codecs
    v2xpki-crypto
    v2xpki-transport
    v2xpki-facade
    EXPORT v2xpki-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/v2xpki/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/v2xpki
    FILES_MATCHING PATTERN "*.hpp"
)

install(FILES ${PROJECT_BINARY_DIR}/include/v2xpki/version.hpp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/v2xpki
)

install(EXPORT v2xpki-targets
    NAMESPACE v2xpki::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/v2xpki
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/v2xpki-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/v2xpki-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/v2xpki-config.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/v2xpki
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/v2xpki-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/v2xpki-config-version.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/v2xpki
)
