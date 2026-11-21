package io.github.xihan123.corehardening.sample.module;

import io.github.xihan123.dex2c.annotation.ProtectionMode;
import io.github.xihan123.dex2c.annotation.dex2c;

public final class ProtectedArithmetic {
    private ProtectedArithmetic() {}

    @dex2c(mode = ProtectionMode.VMP)
    public static int calculate(int x, int y, int z) {
        int addXy = x + y;
        int xorZ = addXy ^ z;
        int subtractZ = x - z;
        int andY = subtractZ & y;
        int product = x * y;
        int orZ = product | z;
        int addYz = y + z;
        int xorX = addYz ^ x;
        int subtractY = z - y;
        int andX = subtractY & x;
        int left = xorZ + andY;
        int right = orZ + xorX;
        return (left + right) + andX;
    }

    @dex2c(mode = ProtectionMode.VMP)
    public static long accumulate(long seed, int rounds) {
        if (rounds < 0 || rounds > 128) {
            throw new IllegalArgumentException("rounds out of range");
        }
        long value = seed;
        for (int i = 0; i < rounds; i++) {
            long scaled = (long) i * 0x9e3779b97f4a7c15L;
            long added = value + scaled;
            long mixed = added ^ (seed >>> (i & 63));
            long offset = seed + (long) i;
            long difference = mixed - offset;
            long spread = difference | (value << (i & 63));
            long folded = spread ^ ((long) i * 0x100000001b3L);
            value = folded + (folded ^ (seed >>> ((i + 11) & 63)));
        }
        return value;
    }
}
