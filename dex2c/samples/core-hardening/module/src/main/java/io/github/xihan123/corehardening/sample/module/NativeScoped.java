package io.github.xihan123.corehardening.sample.module;

public final class NativeScoped {
    static {
        System.loadLibrary("core_cse");
    }

    private NativeScoped() {}

    public static native int check();
}
