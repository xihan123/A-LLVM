#include <stdint.h>

struct Record {
  uint8_t padding[300];
  uint32_t value;
  uint32_t grid[2][3];
  const uint32_t *pointer;
};

uint64_t indexed_records(const struct Record *, int64_t, int);
uint64_t reference_indexed_records(const struct Record *, int64_t, int);
