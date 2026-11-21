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
