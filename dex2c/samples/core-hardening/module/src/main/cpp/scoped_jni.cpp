#include <jni.h>
#include "scoped_consumer.h"

extern "C" JNIEXPORT jint JNICALL
Java_io_github_xihan123_corehardening_sample_module_NativeScoped_check(JNIEnv*, jclass) {
    return core_cse_scoped_probe();
}
