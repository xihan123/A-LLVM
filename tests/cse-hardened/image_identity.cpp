#include "cse_region.h"
extern "C" void image_identity_check(const void* anchor) {
  ndkp_cse_recheck_image_v1(anchor);
}
