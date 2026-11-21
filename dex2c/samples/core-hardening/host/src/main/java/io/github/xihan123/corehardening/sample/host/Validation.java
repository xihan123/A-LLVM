package io.github.xihan123.corehardening.sample.host;

import android.os.Process;
import android.util.Log;

public final class Validation {
    private static final String TAG = "core-hardening";
    private static final int[][] INT_CASES = {
            {0, 0, 0}, {1, 2, 3}, {-1, 17, Integer.MAX_VALUE},
            {Integer.MIN_VALUE, Integer.MAX_VALUE, 1},
            {Integer.MAX_VALUE, Integer.MIN_VALUE, -1},
            {0x7ffffff0, 0x20, 0x10}, {0x80000000, -1, 1},
            {0x12345678, 0x76543210, 0x0f0f0f0f}
    };
    private static final long[] LONG_CASES = {
            0L, 1L, -1L, Long.MIN_VALUE, Long.MAX_VALUE,
            0x7ffffffffffffffeL, 0xfffffffffffffff0L
    };

    private Validation() {}

    public static String run(String processName) {
        try {
            int checked = 0;
            for (int[] values : INT_CASES) {
                int expected = referenceCalculate(values[0], values[1], values[2]);
                int actual = Probe.calculate(values[0], values[1], values[2]);
                require(actual == expected, "calculate", checked, actual, expected);
                checked++;
                int nativeActual = Probe.nativeCalculate(values[0], values[1], values[2]);
                require(nativeActual == expected, "nativeCalculate", checked, nativeActual, expected);
                checked++;
            }
            for (long seed : LONG_CASES) {
                for (int rounds : new int[]{0, 1, 128}) {
                    long expected = referenceAccumulate(seed, rounds);
                    long actual = Probe.accumulate(seed, rounds);
                    require(actual == expected, "accumulate/" + rounds, checked, actual, expected);
                    checked++;
                }
            }
            requireIllegalRounds(-1);
            checked++;
            requireIllegalRounds(129);
            checked++;
            String result = "PASS process=" + processName + " pid=" + Process.myPid()
                    + " cases=" + checked + " intCases=" + INT_CASES.length
                    + " nativeIntCases=" + INT_CASES.length
                    + " longCases=" + (LONG_CASES.length * 3)
                    + " exceptionCases=2";
            Log.i(TAG, result);
            return result;
        } catch (Throwable error) {
            String result = "FAIL process=" + processName + " pid=" + Process.myPid()
                    + " reason=" + error;
            Log.e(TAG, result, error);
            return result;
        }
    }

    private static int referenceCalculate(int x, int y, int z) {
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

    private static long referenceAccumulate(long seed, int rounds) {
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

    private static void require(boolean condition, String method, int index, long actual, long expected) {
        if (!condition) {
            throw new AssertionError(method + "[" + index + "] got=" + actual + " expected=" + expected);
        }
    }

    private static void requireIllegalRounds(int rounds) {
        try {
            Probe.accumulate(0L, rounds);
        } catch (IllegalArgumentException error) {
            if (!"rounds out of range".equals(error.getMessage())) {
                throw new AssertionError("accumulate/" + rounds + " message=" + error.getMessage());
            }
            return;
        }
        throw new AssertionError("accumulate/" + rounds + " did not throw");
    }
}
