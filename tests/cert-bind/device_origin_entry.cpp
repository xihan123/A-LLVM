// Installed APK entry point: check both the host DSO and a separately signed module.
#include "apkcert.h"
#include <dlfcn.h>
#include <jni.h>

extern "C" const char* protected_secret(void);
extern "C" int protected_compute(int);
extern "C" __attribute__((visibility("hidden"))) void ndkp_certbind_mix(uint64_t*, uint64_t*);

extern "C" JNIEXPORT void JNICALL Java_com_ndkp_stability_CheckActivity_check(
        JNIEnv* env, jclass, jstring path, jstring module) {
    const char* name = env->GetStringUTFChars(path, nullptr);
    const char* archive = env->GetStringUTFChars(module, nullptr);
    char modulePath[PATH_MAX], result[PATH_MAX], originPath[PATH_MAX];
    const int moduleLen = snprintf(modulePath, sizeof modulePath, "%s!/lib/arm64-v8a/libmodule.so", archive);
    const int resultLen = snprintf(result, sizeof result, "%s", name);
    const int originLen = snprintf(originPath, sizeof originPath, "%s.origin", name);
    env->ReleaseStringUTFChars(module, archive);
    env->ReleaseStringUTFChars(path, name);
    if (moduleLen < 0 || moduleLen >= PATH_MAX || resultLen < 0 || resultLen >= PATH_MAX ||
        originLen < 0 || originLen >= PATH_MAX) return;
    void* handle = dlopen(modulePath, RTLD_NOW | RTLD_GLOBAL);
    using Probe = bool (*)(uint8_t*);
    const auto probe = handle ? reinterpret_cast<Probe>(dlsym(handle, "module_cert_probe")) : nullptr;
    uint8_t own[32], other[32];
    const bool origins = probe && probe(other) && stringarmor::apkcert::certSha256ForLibrary(
        reinterpret_cast<const void*>(&ndkp_certbind_mix), own);
    FILE* f = fopen(originPath, "w");
    if (f) {
        if (origins) {
            for (uint8_t b : own) fprintf(f, "%02x", b);
            fputc('\n', f);
            for (uint8_t b : other) fprintf(f, "%02x", b);
        } else fprintf(f, "origin lookup failed: %s", handle ? "certificate" : dlerror());
        fclose(f);
    }
    if (handle) dlclose(handle);
    f = fopen(result, "w");
    if (!f) return;
    fputs("START", f); fclose(f);
    volatile int input = 7;
    const char* saved = protected_secret();
    bool ok = std::strcmp(saved, "certificate roundtrip") == 0;
    ok &= protected_secret() == saved;
    ok &= protected_compute(input) == 54;
    f = fopen(result, "w");
    if (f) { fputs(ok ? "OK" : "BAD", f); fclose(f); }
}
