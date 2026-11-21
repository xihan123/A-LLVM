package io.github.xihan123.corehardening.sample.host;

public final class Probe {
    private Probe() {}

    public static int calculate(int x, int y, int z) {
        throw new IllegalStateException("LibXposed module is not active");
    }

    public static int nativeCalculate(int x, int y, int z) {
        throw new IllegalStateException("LibXposed module is not active");
    }

    public static long accumulate(long seed, int rounds) {
        throw new IllegalStateException("LibXposed module is not active");
    }
}
