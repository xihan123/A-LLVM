cmake_minimum_required(VERSION 3.20)
project(apkverify_test LANGUAGES C CXX)

set(_ndkp_apkverify_runtime_dir "${CMAKE_CURRENT_SOURCE_DIR}/../../runtime")
set(_ndkp_apkverify_mbedtls_include_dir
    "${_ndkp_apkverify_runtime_dir}/third_party/mbedtls/include")

if(MINGW AND NOT ANDROID)
  if(CMAKE_CROSSCOMPILING)
    message(FATAL_ERROR
            "The MinGW apkverify host requires a runnable formatter capability probe; "
            "cross-compiling is not supported")
  endif()

  set(_ndkp_formatter_check_ids
      "snprintf.normal.return"
      "snprintf.normal.bytes"
      "snprintf.exact.return"
      "snprintf.exact.bytes"
      "snprintf.exact.sentinel"
      "snprintf.truncation.return"
      "snprintf.truncation.bytes"
      "snprintf.truncation.sentinel"
      "snprintf.zero.return"
      "snprintf.zero.untouched"
      "snprintf.null.zero.return"
      "snprintf.one.return"
      "snprintf.one.terminator"
      "snprintf.one.sentinel"
      "vsnprintf.normal.return"
      "vsnprintf.normal.bytes"
      "vsnprintf.truncation.return"
      "vsnprintf.truncation.bytes"
      "vsnprintf.truncation.sentinel"
      "vsnprintf.zero.return"
      "vsnprintf.zero.untouched"
      "vsnprintf.null.zero.return"
      "vsnprintf.one.return"
      "vsnprintf.one.terminator"
      "vsnprintf.one.sentinel")
  set(_ndkp_formatter_expected_lines)
  foreach(_ndkp_formatter_check_id IN LISTS _ndkp_formatter_check_ids)
    list(APPEND _ndkp_formatter_expected_lines
         "PASS ${_ndkp_formatter_check_id}")
  endforeach()
  list(APPEND _ndkp_formatter_expected_lines "SUMMARY checks=25 failures=0")
  string(REPLACE ";" "\n" _ndkp_formatter_expected_output
         "${_ndkp_formatter_expected_lines}")

  function(_ndkp_run_formatter_probe _language _source)
    string(TOUPPER "${_language}" _ndkp_upper_language)

    set(_ndkp_run_var
        NDKP_APKVERIFY_FORMATTER_${_ndkp_upper_language}_RUN_RESULT)
    set(_ndkp_compile_var
        NDKP_APKVERIFY_FORMATTER_${_ndkp_upper_language}_COMPILE_RESULT)
    set(_ndkp_run_output_var
        NDKP_APKVERIFY_FORMATTER_${_ndkp_upper_language}_RUN_OUTPUT)
    set(_ndkp_compile_output_var
        NDKP_APKVERIFY_FORMATTER_${_ndkp_upper_language}_COMPILE_OUTPUT)
    set(_ndkp_probe_binary_dir
        "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/ndkp_apkverify_formatter_${_language}_try_run")

    foreach(_ndkp_cache_var IN ITEMS
            "${_ndkp_run_var}"
            "${_ndkp_compile_var}"
            "${_ndkp_run_output_var}"
            "${_ndkp_compile_output_var}")
      unset(${_ndkp_cache_var})
      unset(${_ndkp_cache_var} CACHE)
    endforeach()
    set(_ndkp_probe_include_flags
        "-DINCLUDE_DIRECTORIES:STRING=${_ndkp_apkverify_runtime_dir};${_ndkp_apkverify_mbedtls_include_dir}")
    set(_ndkp_probe_definitions
        "-DMBEDTLS_CONFIG_FILE=\"apkverify_mbedtls_config.h\""
        -DMBEDTLS_PLATFORM_C
        -DMBEDTLS_PLATFORM_SNPRINTF_MACRO=snprintf
        -DMBEDTLS_PLATFORM_VSNPRINTF_MACRO=vsnprintf)
    try_run(${_ndkp_run_var} ${_ndkp_compile_var}
            "${_ndkp_probe_binary_dir}" "${_source}"
            CMAKE_FLAGS "${_ndkp_probe_include_flags}"
            COMPILE_DEFINITIONS ${_ndkp_probe_definitions}
            COMPILE_OUTPUT_VARIABLE ${_ndkp_compile_output_var}
            RUN_OUTPUT_VARIABLE ${_ndkp_run_output_var})

    if(NOT "${${_ndkp_compile_var}}")
      message(FATAL_ERROR
              "The MinGW ${_language} formatter capability probe did not compile:\n"
              "${${_ndkp_compile_output_var}}")
    endif()
    if(NOT "${${_ndkp_run_var}}" STREQUAL "0")
      message(FATAL_ERROR
              "The MinGW ${_language} formatter capability probe did not run successfully "
              "(result=${${_ndkp_run_var}}):\n"
              "${${_ndkp_run_output_var}}")
    endif()
    string(REPLACE "\r\n" "\n" _ndkp_formatter_output
                   "${${_ndkp_run_output_var}}")
    string(REPLACE "\r" "\n" _ndkp_formatter_output "${_ndkp_formatter_output}")
    string(STRIP "${_ndkp_formatter_output}" _ndkp_formatter_output)
    if(NOT "${_ndkp_formatter_output}" STREQUAL "${_ndkp_formatter_expected_output}")
      message(FATAL_ERROR
              "The MinGW ${_language} formatter capability probe produced unexpected output:\n"
              "${_ndkp_formatter_output}")
    endif()
  endfunction()

  _ndkp_run_formatter_probe(
    C "${CMAKE_CURRENT_SOURCE_DIR}/formatter_probe.c")
  _ndkp_run_formatter_probe(
    CXX "${CMAKE_CURRENT_SOURCE_DIR}/formatter_probe.cpp")

endif()

include(../../runtime/apkverify_crypto.cmake)
if(MINGW AND NOT ANDROID)
  target_compile_definitions(ndkp_apkcrypto PUBLIC
    MBEDTLS_PLATFORM_C
    MBEDTLS_PLATFORM_SNPRINTF_MACRO=snprintf
    MBEDTLS_PLATFORM_VSNPRINTF_MACRO=vsnprintf)

  add_executable(apkverify_formatter_c formatter_probe.c)
  target_link_libraries(apkverify_formatter_c PRIVATE ndkp_apkcrypto)
  target_compile_features(apkverify_formatter_c PRIVATE c_std_99)

  add_executable(apkverify_formatter_cpp formatter_probe.cpp)
  target_link_libraries(apkverify_formatter_cpp PRIVATE ndkp_apkcrypto)
  target_compile_features(apkverify_formatter_cpp PRIVATE cxx_std_17)
endif()

add_executable(apkverify_probe probe.cpp ../../runtime/apkverify.cpp)
target_link_libraries(apkverify_probe PRIVATE ndkp_apkcrypto)
target_compile_features(apkverify_probe PRIVATE cxx_std_17)

if(ANDROID)
  target_link_options(apkverify_probe PRIVATE -static-libstdc++)
endif()
