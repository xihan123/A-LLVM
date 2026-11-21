package io.github.xihan123.corehardening.sample.module;

public final class NativeFusion {
    static {
        System.loadLibrary("core_fusion");
    }

    private NativeFusion() {}

    public static native int calculate(int x, int y, int z);
}
