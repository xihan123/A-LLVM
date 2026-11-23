package sample;

import io.github.xihan123.dex2c.annotation.dex2c;
import io.github.xihan123.dex2c.annotation.ProtectionMode;

public class Run {
    @dex2c(mode = ProtectionMode.NATIVE, integrityRecheck = true)
    static int commit(int value) { return value * 3 + 7; }

    public static void main(String[] args) {
        for (int value : new int[]{0, 1, -1, Integer.MAX_VALUE, Integer.MIN_VALUE})
            if (commit(value) != value * 3 + 7) throw new AssertionError("native checkpoint");
        System.out.println("zero-pool native checkpoint: OK");
    }
}
