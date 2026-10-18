#include <stdint.h>
#include "global_slots.h"

#ifdef REFERENCE
#define global_roundtrip reference_global_roundtrip
#define global_tls reference_global_tls
#define indexed_records reference_indexed_records
#endif

static volatile uint32_t count;
static uint32_t *pointer;

// i32 地址槽曾只预留 4 字节，wrapper 的 8 字节写入破坏相邻槽。
__attribute__((noinline)) uint32_t global_roundtrip(uint32_t *p, uint32_t x) {
  pointer = p;
  count = x;
  *pointer = count;
  return *pointer + count;
}

static _Thread_local volatile uint8_t byte_value;
static _Thread_local volatile uint16_t short_value;
static _Thread_local volatile uint32_t int_value;
static _Thread_local volatile uint64_t wide_value;
static _Thread_local uint32_t *first_pointer;
static _Thread_local uint32_t *second_pointer;
static _Thread_local volatile struct { uint8_t values[3]; } small_array;

__attribute__((noinline)) uint64_t global_tls(uint32_t *a, uint32_t *b, uint32_t x) {
  first_pointer = a;
  second_pointer = b;
  byte_value = x;
  short_value = x ^ 0x1234u;
  int_value = x * 0x10203u;
  wide_value = ((uint64_t)x << 40) | x;
  small_array.values[1] = x >> 1;
  *first_pointer = int_value + byte_value;
  *second_pointer = short_value + small_array.values[1];
  return wide_value ^ ((uint64_t)*first_pointer << 32) ^ *second_pointer;
}

__attribute__((noinline)) uint64_t indexed_records(const struct Record *records, int64_t i, int j) {
  return ((uint64_t)records[i].value << 32) + records[i].grid[1][j] + *records[i].pointer;
}

#ifndef REFERENCE
typedef int (*callback_fn)(int);
extern int external_callback(int);
__attribute__((noinline)) int callback_identity(int n) { return n + 17; }
int callback_alias(int) __attribute__((alias("callback_identity")));

// 函数和别名曾被编码为数据槽 0，返回与保存回调地址会变成空指针。
__attribute__((noinline)) callback_fn pick_callback(unsigned n, callback_fn *out) {
  callback_fn selected;
  switch (n) {
    case 0: selected = callback_identity; break;
    case 1: selected = external_callback; break;
    case 2: selected = callback_alias; break;
    default: selected = 0; break;
  }
  *out = selected;
  return selected;
}
#endif
