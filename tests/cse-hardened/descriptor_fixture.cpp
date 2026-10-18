extern "C" const char* long_value() { return "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"; }
extern "C" const char* short_value() { return "ok"; }

#include "ndkp.h"
extern "C"
#ifndef NDKP_TEST_NO_RECHECK
NDKP_CSE_RECHECK
#endif
int checkpoint(int value) { return value * 3 + 7; }

extern "C" {
#ifndef NDKP_TEST_NO_RECHECK
NDKP_CSE_RECHECK
#endif
static int unused_gate(int value) { return value + 1; }
int unchecked_caller(int value) {
  unused_gate(value);
  return value * 3 + 7;
}
}
