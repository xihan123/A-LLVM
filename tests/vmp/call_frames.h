#ifndef NDKP_VMP_CALL_FRAMES_TEST_H
#define NDKP_VMP_CALL_FRAMES_TEST_H
#include <stdint.h>
#ifdef REFERENCE
#define frame_write reference_frame_write
#define frame_local reference_frame_local
#define frame_direct reference_frame_direct
#define frame_vm reference_frame_vm
#define frame_external reference_frame_external
#define frame_pointer reference_frame_pointer
#define frame_alias reference_frame_alias
#define frame_recursive reference_frame_recursive
#define frame_reentrant reference_frame_reentrant
#define frame_make reference_frame_make
#define frame_sret reference_frame_sret
#define frame_catch reference_frame_catch
#define frame_escape reference_frame_escape
#endif
struct FrameWords { uint64_t a, b, c, d; };
extern "C" {
int native_frame_write(int *);
__attribute__((noinline)) int frame_write(int *);
__attribute__((noinline)) int frame_local(int (*)(int *));
__attribute__((noinline)) int frame_direct();
__attribute__((noinline)) int frame_vm();
__attribute__((noinline)) int frame_external(int (*)(int *), int *);
__attribute__((noinline)) int frame_pointer(int (*)(void **), void *);
__attribute__((noinline)) int frame_alias(void (*)(int *, int *));
__attribute__((noinline)) int frame_recursive(int, int *);
__attribute__((noinline)) int frame_reentrant(int, int *, int (*)(int, int *));
__attribute__((noinline)) FrameWords frame_make(uint64_t);
__attribute__((noinline)) uint64_t frame_sret(uint64_t);
__attribute__((noinline)) int frame_catch(int (*)(int *, int), int);
__attribute__((noinline)) int frame_escape(int (*)(int *, int), int *, int);
}
#endif
