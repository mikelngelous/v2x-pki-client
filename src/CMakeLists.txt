# codecs
file(GLOB PKI_CODEC_SOURCES CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/generated/*.c)
list(LENGTH PKI_CODEC_SOURCES PKI_CODEC_SOURCE_COUNT)
message(STATUS "v2xpki-codecs: ${PKI_CODEC_SOURCE_COUNT} sources")

add_library(v2xpki-codecs STATIC ${PKI_CODEC_SOURCES})
target_include_directories(v2xpki-codecs PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/generated>
)
target_compile_options(v2xpki-codecs PRIVATE -w -fno-strict-aliasing)
set_target_properties(v2xpki-codecs PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    EXPORT_NAME codecs
)

# crypto
add_library(v2xpki-crypto STATIC
    crypto_ec.cpp
    ecies.cpp
    plaintext_file_key_store.cpp
)
target_link_libraries(v2xpki-crypto PUBLIC v2xpki-codecs OpenSSL::Crypto)
target_include_directories(v2xpki-crypto PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(v2xpki-crypto PUBLIC cxx_std_17)
set_target_properties(v2xpki-crypto PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    EXPORT_NAME crypto
)

# transport
add_library(v2xpki-transport STATIC
    internal/coer.cpp
    internal/curve_point.cpp
    internal/cert_parse.cpp
    internal/signed_message.cpp
    internal/encrypted_data.cpp
    internal/signed_envelope.cpp
    http_client.cpp
    trust_chain.cpp
    trust_list.cpp
    revocation.cpp
)
target_link_libraries(v2xpki-transport PUBLIC v2xpki-crypto CURL::libcurl)
target_include_directories(v2xpki-transport PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(v2xpki-transport PUBLIC cxx_std_17)
set_target_properties(v2xpki-transport PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    EXPORT_NAME transport
)

# facade
add_library(v2xpki-facade STATIC
    ec_request.cpp
    at_request.cpp
    pki_client.cpp
)
target_link_libraries(v2xpki-facade PUBLIC v2xpki-transport)
target_include_directories(v2xpki-facade PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(v2xpki-facade PUBLIC cxx_std_17)
set_target_properties(v2xpki-facade PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    EXPORT_NAME facade
)

# cli
add_executable(v2x-pki-client
    main.cpp
    cli/args.cpp
    cli/io.cpp
    cli/commands.cpp
)
target_include_directories(v2x-pki-client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(v2x-pki-client PRIVATE v2xpki-facade)
target_compile_features(v2x-pki-client PRIVATE cxx_std_17)

# tests (declared in src/test/CMakeLists.txt)
if(V2XPKI_BUILD_TESTS)
    add_subdirectory(test)
endif()
