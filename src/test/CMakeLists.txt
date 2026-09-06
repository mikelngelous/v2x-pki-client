# Unit + integration tests — GoogleTest harness.

include(GoogleTest)

add_executable(test_round_trip_pki test_round_trip_pki.cpp)
target_link_libraries(test_round_trip_pki PRIVATE v2xpki-codecs GTest::gtest_main)
target_compile_features(test_round_trip_pki PRIVATE cxx_std_17)
gtest_discover_tests(test_round_trip_pki TEST_PREFIX pki_codecs.)

add_executable(test_crypto_ec test_crypto_ec.cpp)
target_link_libraries(test_crypto_ec PRIVATE v2xpki-crypto GTest::gtest_main)
gtest_discover_tests(test_crypto_ec TEST_PREFIX pki.)

add_executable(test_key_store test_key_store.cpp)
target_link_libraries(test_key_store PRIVATE v2xpki-crypto GTest::gtest_main)
gtest_discover_tests(test_key_store TEST_PREFIX pki.)

add_executable(test_result test_result.cpp)
target_link_libraries(test_result PRIVATE v2xpki-facade GTest::gtest_main)
gtest_discover_tests(test_result TEST_PREFIX pki.)

add_executable(test_request_hash test_request_hash.cpp)
target_include_directories(test_request_hash PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(test_request_hash PRIVATE v2xpki-crypto GTest::gtest_main)
gtest_discover_tests(test_request_hash TEST_PREFIX pki.)

add_executable(test_static_bytes test_static_bytes.cpp)
target_include_directories(test_static_bytes PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(test_static_bytes PRIVATE GTest::gtest_main)
target_compile_features(test_static_bytes PRIVATE cxx_std_17)
gtest_discover_tests(test_static_bytes TEST_PREFIX pki.)

add_executable(test_http_client test_http_client.cpp)
target_link_libraries(test_http_client PRIVATE v2xpki-transport GTest::gtest_main)
gtest_discover_tests(test_http_client TEST_PREFIX pki.)

add_executable(test_trust_chain test_trust_chain.cpp)
target_include_directories(test_trust_chain PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(test_trust_chain PRIVATE v2xpki-transport GTest::gtest_main)
gtest_discover_tests(test_trust_chain TEST_PREFIX pki.)

add_executable(test_revocation test_revocation.cpp)
target_link_libraries(test_revocation PRIVATE v2xpki-transport GTest::gtest_main)
gtest_discover_tests(test_revocation TEST_PREFIX pki.)

add_executable(test_crl_decode test_crl_decode.cpp)
target_include_directories(test_crl_decode PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(test_crl_decode PRIVATE v2xpki-transport GTest::gtest_main)
gtest_discover_tests(test_crl_decode TEST_PREFIX pki.)

add_executable(test_response_auth test_response_auth.cpp)
target_include_directories(test_response_auth PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(test_response_auth PRIVATE v2xpki-transport GTest::gtest_main)
gtest_discover_tests(test_response_auth TEST_PREFIX pki.)

add_executable(test_whole_cert_hash test_whole_cert_hash.cpp)
target_include_directories(test_whole_cert_hash PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(test_whole_cert_hash PRIVATE
    FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
target_link_libraries(test_whole_cert_hash PRIVATE v2xpki-transport GTest::gtest_main)
gtest_discover_tests(test_whole_cert_hash TEST_PREFIX pki.)

add_executable(test_trust_list test_trust_list.cpp)
target_link_libraries(test_trust_list PRIVATE v2xpki-facade GTest::gtest_main)
gtest_discover_tests(test_trust_list TEST_PREFIX pki.)

add_executable(test_ec_request test_ec_request.cpp)
target_link_libraries(test_ec_request PRIVATE v2xpki-facade GTest::gtest_main)
gtest_discover_tests(test_ec_request TEST_PREFIX pki.)

add_executable(test_at_request test_at_request.cpp)
target_link_libraries(test_at_request PRIVATE v2xpki-facade GTest::gtest_main)
gtest_discover_tests(test_at_request TEST_PREFIX pki.)

add_executable(test_facade test_facade.cpp)
target_link_libraries(test_facade PRIVATE v2xpki-facade GTest::gtest_main)
gtest_discover_tests(test_facade TEST_PREFIX pki.)

add_executable(test_dc_url test_dc_url.cpp)
target_link_libraries(test_dc_url PRIVATE v2xpki-facade GTest::gtest_main)
gtest_discover_tests(test_dc_url TEST_PREFIX pki.)

# Integration test — hits Castell LIVE; manual add_test (no gtest_discover_tests).
add_executable(test_integration_castell test_integration_castell.cpp)
target_link_libraries(test_integration_castell PRIVATE v2xpki-facade GTest::gtest_main)
target_include_directories(test_integration_castell PRIVATE ${PROJECT_SOURCE_DIR}/src)
add_test(NAME pki.integration_castell COMMAND test_integration_castell)
set_tests_properties(pki.integration_castell PROPERTIES LABELS live)

add_executable(test_canonical_id test_canonical_id.cpp)
target_link_libraries(test_canonical_id PRIVATE v2xpki-facade GTest::gtest_main)
target_include_directories(test_canonical_id PRIVATE ${PROJECT_SOURCE_DIR}/src)
gtest_discover_tests(test_canonical_id TEST_PREFIX pki.)

add_executable(test_golden_bytes test_golden_bytes.cpp)
target_link_libraries(test_golden_bytes PRIVATE v2xpki-transport GTest::gtest_main)
target_include_directories(test_golden_bytes PRIVATE ${PROJECT_SOURCE_DIR}/src)
gtest_discover_tests(test_golden_bytes TEST_PREFIX pki.)
