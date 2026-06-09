add_executable(at-rotator at-rotator.cpp)
target_link_libraries(at-rotator PRIVATE v2xpki-facade)
target_compile_features(at-rotator PRIVATE cxx_std_17)
