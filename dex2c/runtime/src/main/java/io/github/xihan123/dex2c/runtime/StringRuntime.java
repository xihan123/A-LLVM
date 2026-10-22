package io.github.xihan123.dex2c.runtime;

import java.util.concurrent.atomic.AtomicReferenceArray;

/** Copied and renamed per artifact; loading the class does not load native code. */
public final class StringRuntime {
    private static final AtomicReferenceArray<String> CACHE = new AtomicReferenceArray<>(size());
    private static final Object[] LOCKS = new Object[16];
    private static volatile boolean loaded;
    static {
        for (int i = 0; i < LOCKS.length; i++) LOCKS[i] = new Object();
    }
    private StringRuntime() {}
    private static int size() { return 0; }
    private static String library() { return ""; }

    private static synchronized void load() {
        if (!loaded) {
            System.loadLibrary(library());
            loaded = true;
        }
    }

    public static String get(int index) {
        String value = CACHE.get(index);
        if (value != null) return value;
        load();
        synchronized (LOCKS[index & (LOCKS.length - 1)]) {
            value = CACHE.get(index);
            if (value == null) {
                value = decode(index);
                if (value == null) throw new LinkageError("Native string returned null");
                value = value.intern();
                CACHE.set(index, value);
            }
        }
        return value;
    }

    private static native String decode(int index);
}
