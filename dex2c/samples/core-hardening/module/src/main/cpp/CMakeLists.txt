cmake_minimum_required(VERSION 3.22)
project(core_fusion LANGUAGES CXX)

if(NOT CORE_FUSION_CLANG)
    message(FATAL_ERROR "CORE_FUSION_CLANG must point to the patched Clang")
endif()
if(NOT CMAKE_ANDROID_NDK)
    message(FATAL_ERROR "CMAKE_ANDROID_NDK is required for core_fusion")
endif()

if(CMAKE_HOST_WIN32)
    set(CORE_FUSION_LLVM_HOST windows-x86_64)
elseif(CMAKE_HOST_APPLE)
    set(CORE_FUSION_LLVM_HOST darwin-x86_64)
else()
    set(CORE_FUSION_LLVM_HOST linux-x86_64)
endif()

set(CORE_FUSION_NDK_LLVM
    "${CMAKE_ANDROID_NDK}/toolchains/llvm/prebuilt/${CORE_FUSION_LLVM_HOST}")
set(CORE_FUSION_SYSROOT "${CORE_FUSION_NDK_LLVM}/sysroot")
set(CORE_FUSION_RESOURCE_DIR "${CORE_FUSION_NDK_LLVM}/lib/clang/21")
get_filename_component(CORE_FUSION_REPO_ROOT
    "${CMAKE_CURRENT_LIST_DIR}/../../../../../../.." ABSOLUTE)
set(CORE_FUSION_INCLUDE "${CORE_FUSION_REPO_ROOT}/include")
set(CORE_FUSION_SOURCE "${CMAKE_CURRENT_LIST_DIR}/arithmetic.cpp")
set(CORE_FUSION_NDKP_HEADER "${CORE_FUSION_INCLUDE}/ndkp.h")
set(CORE_FUSION_RAW_IR "${CMAKE_CURRENT_BINARY_DIR}/arithmetic.raw.ll")
set(CORE_FUSION_POST_IR "${CMAKE_CURRENT_BINARY_DIR}/arithmetic.ll")
set(CORE_FUSION_OBJECT "${CMAKE_CURRENT_BINARY_DIR}/arithmetic.o")

add_custom_command(
    OUTPUT "${CORE_FUSION_RAW_IR}" "${CORE_FUSION_POST_IR}" "${CORE_FUSION_OBJECT}"
    COMMAND "${CORE_FUSION_CLANG}"
        --target=aarch64-linux-android26
        "--sysroot=${CORE_FUSION_SYSROOT}"
        "-resource-dir=${CORE_FUSION_RESOURCE_DIR}"
        "-I${CORE_FUSION_INCLUDE}"
        --driver-mode=g++
        -O1 -fPIC -fvisibility=hidden -frtti -fno-exceptions
        -mllvm -irobf-vmp
        -mllvm -irobf-vmp-strict
        -fno-discard-value-names
        -S -emit-llvm "${CORE_FUSION_SOURCE}" -o "${CORE_FUSION_RAW_IR}"
    COMMAND "${CORE_FUSION_CLANG}"
        --target=aarch64-linux-android26
        "--sysroot=${CORE_FUSION_SYSROOT}"
        "-resource-dir=${CORE_FUSION_RESOURCE_DIR}"
        --driver-mode=g++
        -Oz -mllvm -irobf-vmp-post
        -fPIC -fno-discard-value-names
        -S -emit-llvm "${CORE_FUSION_RAW_IR}" -o "${CORE_FUSION_POST_IR}"
    COMMAND "${CORE_FUSION_CLANG}"
        --target=aarch64-linux-android26
        "--sysroot=${CORE_FUSION_SYSROOT}"
        "-resource-dir=${CORE_FUSION_RESOURCE_DIR}"
        --driver-mode=g++
        -Oz -Xclang -disable-llvm-passes
        -fPIC
        -c "${CORE_FUSION_POST_IR}" -o "${CORE_FUSION_OBJECT}"
    DEPENDS "${CORE_FUSION_SOURCE}" "${CORE_FUSION_NDKP_HEADER}"
            "${CORE_FUSION_CLANG}"
    VERBATIM
    COMMENT "Building core_fusion arithmetic with patched Clang"
)

set_source_files_properties("${CORE_FUSION_OBJECT}" PROPERTIES GENERATED TRUE)
add_library(core_fusion SHARED jni.cpp "${CORE_FUSION_OBJECT}")
target_compile_options(core_fusion PRIVATE -fvisibility=hidden)
target_link_options(core_fusion PRIVATE
    "-Wl,--no-undefined"
    "-Wl,-z,max-page-size=16384")

option(CORE_CSE_SCOPED "Build the independent scoped CSE probe" OFF)
if(CORE_CSE_SCOPED)
    if(NOT CORE_CSE_CERTIFICATE OR NOT EXISTS "${CORE_CSE_CERTIFICATE}")
        message(FATAL_ERROR "CORE_CSE_CERTIFICATE must be the module APK signer certificate")
    endif()
    if(NOT CORE_CSE_PYTHON)
        find_package(Python3 REQUIRED COMPONENTS Interpreter)
        set(CORE_CSE_PYTHON "${Python3_EXECUTABLE}")
    endif()
    set(CORE_CSE_PACKAGE "io.github.xihan123.corehardening.sample.host")
    set(CORE_CSE_RUNTIME "${CORE_FUSION_REPO_ROOT}/runtime")
    set(CORE_CSE_SCOPE_IR "${CMAKE_CURRENT_BINARY_DIR}/scoped.ll")
    set(CORE_CSE_SCOPE_OBJECT "${CMAKE_CURRENT_BINARY_DIR}/scoped.o")
    set(CORE_CSE_RUNTIME_RAW "${CMAKE_CURRENT_BINARY_DIR}/cse-runtime.raw.ll")
    set(CORE_CSE_RUNTIME_IR "${CMAKE_CURRENT_BINARY_DIR}/cse-runtime.ll")
    set(CORE_CSE_RUNTIME_OBJECT "${CMAKE_CURRENT_BINARY_DIR}/cse-runtime.o")
    set(CORE_CSE_COMMON
        --target=aarch64-linux-android26 "--sysroot=${CORE_FUSION_SYSROOT}"
        "-resource-dir=${CORE_FUSION_RESOURCE_DIR}" "-B${CORE_FUSION_NDK_LLVM}/bin"
        --driver-mode=g++ -std=c++17 -fPIC -fvisibility=hidden -fno-lto
        -frtti -fno-exceptions -femulated-tls)
    add_custom_command(
        OUTPUT "${CORE_CSE_SCOPE_IR}" "${CORE_CSE_SCOPE_OBJECT}"
        COMMAND "${CORE_FUSION_CLANG}" ${CORE_CSE_COMMON} "-I${CORE_FUSION_INCLUDE}"
            -O2 -fno-discard-value-names
            -mllvm -irobf-cse -mllvm -irobf-cse-hardened -mllvm -irobf-cse-scoped
            -mllvm -irobf-cse-bind "-mllvm" "-irobf-cse-bind-package=${CORE_CSE_PACKAGE}"
            -mllvm -irobf-cert-bind "-mllvm" "-irobf-cert-file=${CORE_CSE_CERTIFICATE}"
            -S -emit-llvm "${CMAKE_CURRENT_LIST_DIR}/scoped.cpp" -o "${CORE_CSE_SCOPE_IR}"
        COMMAND "${CORE_FUSION_CLANG}" ${CORE_CSE_COMMON} -Oz -Xclang -disable-llvm-passes
            -c "${CORE_CSE_SCOPE_IR}" -o "${CORE_CSE_SCOPE_OBJECT}"
        DEPENDS "${CMAKE_CURRENT_LIST_DIR}/scoped.cpp" "${CMAKE_CURRENT_LIST_DIR}/scoped_consumer.h"
                "${CORE_FUSION_NDKP_HEADER}" "${CORE_CSE_CERTIFICATE}" "${CORE_FUSION_CLANG}"
        VERBATIM
        COMMENT "Building scoped CSE business TU")
    add_custom_command(
        OUTPUT "${CORE_CSE_RUNTIME_RAW}" "${CORE_CSE_RUNTIME_IR}" "${CORE_CSE_RUNTIME_OBJECT}"
        COMMAND "${CORE_FUSION_CLANG}" ${CORE_CSE_COMMON} -O1 -fno-discard-value-names
            -fno-vectorize -fno-slp-vectorize -fno-unroll-loops -DNDKP_CSE_VMP
            -mllvm -irobf-vmp -mllvm -irobf-vmp-strict -mllvm -irobf-vmp-memops
            -mllvm -irobf-selfcheck -mllvm -irobf-selfcheck-entry
            -S -emit-llvm "${CORE_CSE_RUNTIME}/ndkp_cse_runtime.cpp" -o "${CORE_CSE_RUNTIME_RAW}"
        COMMAND "${CORE_FUSION_CLANG}" ${CORE_CSE_COMMON} -Oz -fno-discard-value-names
            -mllvm -irobf-vmp-post -S -emit-llvm "${CORE_CSE_RUNTIME_RAW}" -o "${CORE_CSE_RUNTIME_IR}"
        COMMAND "${CORE_FUSION_CLANG}" ${CORE_CSE_COMMON} -Oz -Xclang -disable-llvm-passes
            -c "${CORE_CSE_RUNTIME_IR}" -o "${CORE_CSE_RUNTIME_OBJECT}"
        DEPENDS "${CORE_CSE_RUNTIME}/ndkp_cse_runtime.cpp" "${CORE_CSE_RUNTIME}/cse_region.h"
                "${CORE_CSE_RUNTIME}/cse_crypto.h" "${CORE_CSE_RUNTIME}/sha256.h"
                "${CORE_CSE_RUNTIME}/apkcert.h" "${CORE_CSE_RUNTIME}/apkcert_io.h"
                "${CORE_FUSION_CLANG}"
        VERBATIM
        COMMENT "Building separate CSE crypto runtime with strict VMP and post")
    set_source_files_properties("${CORE_CSE_SCOPE_OBJECT}" "${CORE_CSE_RUNTIME_OBJECT}"
        PROPERTIES GENERATED TRUE EXTERNAL_OBJECT TRUE)
    add_library(core_cse SHARED scoped_jni.cpp scoped_consumer.cpp
        "${CORE_CSE_SCOPE_OBJECT}" "${CORE_CSE_RUNTIME_OBJECT}")
    target_compile_options(core_cse PRIVATE -fvisibility=hidden -fno-lto -fno-exceptions)
    target_link_libraries(core_cse PRIVATE dl)
    target_link_options(core_cse PRIVATE "-Wl,--no-undefined" "-Wl,-z,max-page-size=16384")
    add_custom_command(TARGET core_cse POST_BUILD
        COMMAND "${CORE_CSE_PYTHON}" "${CORE_FUSION_REPO_ROOT}/scripts/seal_cse.py"
            --input "$<TARGET_FILE:core_cse>" --output "$<TARGET_FILE:core_cse>.sealed"
            --package "${CORE_CSE_PACKAGE}" --cert-file "${CORE_CSE_CERTIFICATE}"
        COMMAND "${CMAKE_COMMAND}" -E rename "$<TARGET_FILE:core_cse>.sealed" "$<TARGET_FILE:core_cse>"
        COMMAND "${CORE_CSE_PYTHON}" "${CORE_FUSION_REPO_ROOT}/scripts/seal_cse.py"
            --input "$<TARGET_FILE:core_cse>" --verify
            --package "${CORE_CSE_PACKAGE}" --cert-file "${CORE_CSE_CERTIFICATE}"
        VERBATIM
        COMMENT "Sealing and verifying scoped CSE for the module signer and host process")
endif()
