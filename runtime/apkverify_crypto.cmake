# Verification only: no TLS, networking, entropy, private-key storage or PSA runtime.
file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/apkverify_sources.txt" NDKP_MBEDTLS_SOURCES)
list(TRANSFORM NDKP_MBEDTLS_SOURCES PREPEND "${CMAKE_CURRENT_LIST_DIR}/third_party/mbedtls/library/")
list(TRANSFORM NDKP_MBEDTLS_SOURCES APPEND ".c")
add_library(ndkp_apkcrypto STATIC ${NDKP_MBEDTLS_SOURCES})
target_include_directories(ndkp_apkcrypto PUBLIC "${CMAKE_CURRENT_LIST_DIR}/third_party/mbedtls/include" "${CMAKE_CURRENT_LIST_DIR}")
target_compile_definitions(ndkp_apkcrypto PUBLIC MBEDTLS_CONFIG_FILE="apkverify_mbedtls_config.h")
set_target_properties(ndkp_apkcrypto PROPERTIES POSITION_INDEPENDENT_CODE ON INTERPROCEDURAL_OPTIMIZATION OFF)
