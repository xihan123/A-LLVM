#include "ndkp.h"
#include "scoped_consumer.h"

extern "C" NDKP_CSE_SCOPED int core_cse_scoped_probe() noexcept {
    uint32_t bytes = core_cse_hash8("NDKP_CORE_SCOPED_p30_9b6d", 26);
    uint32_t words = core_cse_hash16(u"scope \u4e2d\u6587", 9);
    return bytes == 0x1cb3380bu && words == 0x34574550u ? 0 : 1;
}
