#include <stdint.h>

#include "ndkp.h"

extern "C" NDKP_VMP uint32_t core_fusion_calculate(uint32_t x, uint32_t y, uint32_t z) {
  uint32_t addXy = x + y;
  uint32_t xorZ = addXy ^ z;
  uint32_t subtractZ = x - z;
  uint32_t andY = subtractZ & y;
  uint32_t product = x * y;
  uint32_t orZ = product | z;
  uint32_t addYz = y + z;
  uint32_t xorX = addYz ^ x;
  uint32_t subtractY = z - y;
  uint32_t andX = subtractY & x;
  uint32_t left = xorZ + andY;
  uint32_t right = orZ + xorX;
  return (left + right) + andX;
}
