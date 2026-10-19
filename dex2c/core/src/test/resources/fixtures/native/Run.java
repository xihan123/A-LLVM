package sample;

import io.github.xihan123.dex2c.annotation.dex2c;
import io.github.xihan123.dex2c.annotation.ProtectionMode;
import java.util.function.IntUnaryOperator;

public class Run {
    @dex2c(mode = ProtectionMode.NATIVE)
    static synchronized int work(int[] values, IntUnaryOperator callback) {
        try { return callback.applyAsInt(values[0]) + "native-only".length(); }
        catch (NullPointerException expected) { return -1; }
    }
    public static void main(String[] args) throws Exception {
        Thread[] threads = new Thread[8];
        java.util.concurrent.atomic.AtomicReference<Throwable> failure = new java.util.concurrent.atomic.AtomicReference<>();
        for (int i = 0; i < threads.length; i++) {
            threads[i] = new Thread(() -> {
                try {
                    if (work(new int[]{5}, x -> x * 2) != 21 || work(null, x -> x) != -1)
                        throw new AssertionError();
                } catch (Throwable error) { failure.compareAndSet(null, error); }
            });
            threads[i].start();
        }
        for (Thread thread : threads) thread.join();
        if (failure.get() != null) throw new AssertionError(failure.get());
        System.out.println("native-only=21:-1");
    }
}
