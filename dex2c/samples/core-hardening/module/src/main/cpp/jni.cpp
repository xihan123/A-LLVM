#include <jni.h>
#include <stdint.h>

extern "C" uint32_t core_fusion_calculate(uint32_t x, uint32_t y,
                                           uint32_t z);

extern "C" JNIEXPORT jint JNICALL
Java_io_github_xihan123_corehardening_sample_module_NativeFusion_calculate(
        JNIEnv*, jclass, jint x, jint y, jint z) {
    return static_cast<jint>(core_fusion_calculate(
            static_cast<uint32_t>(x), static_cast<uint32_t>(y),
            static_cast<uint32_t>(z)));
}
