package io.github.xihan123.dex2c.sample.module;

final class ExistingNative {
    private static native int value();
    static void check() {
        System.loadLibrary("coexist");
        if (value() != 102) throw new AssertionError("existing native library");
    }
}
