add_executable(pki-provisioner
    pki-provisioner/main.cpp
    pki-provisioner/flow.cpp
    pki-provisioner/key_pem.cpp
)
target_include_directories(pki-provisioner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pki-provisioner PRIVATE v2xpki-facade)
target_compile_features(pki-provisioner PRIVATE cxx_std_17)
