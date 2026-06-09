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
    crypto_p256.cpp
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
    http_client.cpp
    trust_chain.cpp
    trust_list.cpp
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
add_executable(v2x-pki-client main.cpp)
target_link_libraries(v2x-pki-client PRIVATE v2xpki-facade)
target_compile_features(v2x-pki-client PRIVATE cxx_std_17)

# tests
add_executable(test_round_trip_pki test/test_round_trip_pki.cpp)
target_link_libraries(test_round_trip_pki PRIVATE v2xpki-codecs)
target_compile_features(test_round_trip_pki PRIVATE cxx_std_17)
add_test(NAME pki_codecs.round_trip COMMAND test_round_trip_pki)

add_executable(test_crypto_p256 test/test_crypto_p256.cpp)
target_link_libraries(test_crypto_p256 PRIVATE v2xpki-crypto)
add_test(NAME pki.crypto_p256 COMMAND test_crypto_p256)

add_executable(test_key_store test/test_key_store.cpp)
target_link_libraries(test_key_store PRIVATE v2xpki-crypto)
add_test(NAME pki.key_store COMMAND test_key_store)

add_executable(test_result test/test_result.cpp)
target_link_libraries(test_result PRIVATE v2xpki-facade)
add_test(NAME pki.result COMMAND test_result)

add_executable(test_http_client test/test_http_client.cpp)
target_link_libraries(test_http_client PRIVATE v2xpki-transport)
add_test(NAME pki.http_client COMMAND test_http_client)

add_executable(test_trust_chain test/test_trust_chain.cpp)
target_link_libraries(test_trust_chain PRIVATE v2xpki-transport)
add_test(NAME pki.trust_chain COMMAND test_trust_chain)

add_executable(test_trust_list test/test_trust_list.cpp)
target_link_libraries(test_trust_list PRIVATE v2xpki-facade)
add_test(NAME pki.trust_list COMMAND test_trust_list)

add_executable(test_ec_request test/test_ec_request.cpp)
target_link_libraries(test_ec_request PRIVATE v2xpki-facade)
add_test(NAME pki.ec_request COMMAND test_ec_request)

add_executable(test_at_request test/test_at_request.cpp)
target_link_libraries(test_at_request PRIVATE v2xpki-facade)
add_test(NAME pki.at_request COMMAND test_at_request)

add_executable(test_facade test/test_facade.cpp)
target_link_libraries(test_facade PRIVATE v2xpki-facade)
add_test(NAME pki.facade COMMAND test_facade)

add_executable(test_integration_castell test/test_integration_castell.cpp)
target_link_libraries(test_integration_castell PRIVATE v2xpki-facade)
add_test(NAME pki.integration_castell COMMAND test_integration_castell)
