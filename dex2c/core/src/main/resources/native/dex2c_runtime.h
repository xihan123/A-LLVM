#pragma once
#include <jni.h>
#include <stdint.h>
#include <math.h>

#if defined(D2C_VMP)
#define D2C_PROTECTED __attribute__((annotate("ndkp.vmp"), noinline, used))
#else
#define D2C_PROTECTED
#endif

struct d2c_slot { jvalue v; bool reference; uint64_t uninitialized; };
struct d2c_frame { JNIEnv* env; jclass owner; d2c_slot* slots; int count; uint64_t allocation; };
d2c_frame* d2c_open(JNIEnv*, jclass, int);
jobject d2c_close(d2c_frame*, jobject);
void d2c_ref(d2c_frame*, int, jobject);
void d2c_copy(d2c_frame*, int, int);
void d2c_i(d2c_frame*, int, jint);
void d2c_j(d2c_frame*, int, jlong);
void d2c_f(d2c_frame*, int, jfloat);
void d2c_d(d2c_frame*, int, jdouble);
jclass d2c_class(d2c_frame*, const char*, bool initialize = false);
void d2c_register(JNIEnv*, jclass, const JNINativeMethod*, int);
jobject d2c_string(d2c_frame*, const jchar*, int);
void d2c_allocate(d2c_frame*, int, const char*);
void d2c_new_array(d2c_frame*, int, int, jint);
void d2c_object_array(d2c_frame*, int, const char*, jint);
void d2c_multi_array(d2c_frame*, int, const char*, int);
jint d2c_array_length(d2c_frame*, jobject);
void d2c_array_load(d2c_frame*, int, int);
void d2c_array_store(d2c_frame*, int, int);
void d2c_field(d2c_frame*, int, const char*, const char*, const char*, bool, bool);
void d2c_invoke(d2c_frame*, int, const char*, const char*, const char*, int, int);
jint d2c_instance(d2c_frame*, jobject, const char*);
void d2c_cast(d2c_frame*, int, const char*);
void d2c_throw(d2c_frame*, jobject);
void d2c_monitor(d2c_frame*, jobject, bool);
bool d2c_catch(d2c_frame*, const char*, int);
jint d2c_idiv(d2c_frame*, jint, jint, bool);
jlong d2c_jdiv(d2c_frame*, jlong, jlong, bool);
jint d2c_to_i(double);
jlong d2c_to_j(double);
jfloat d2c_float(uint32_t);
jdouble d2c_double(uint64_t);
