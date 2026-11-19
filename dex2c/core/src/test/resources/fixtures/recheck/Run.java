package sample;

import io.github.xihan123.dex2c.annotation.dex2c;
import io.github.xihan123.dex2c.annotation.ProtectionMode;

/** Low-frequency entry fixture; hot/helper methods deliberately have no checkpoint. */
public class Run {
    @dex2c(integrityRecheck = true)
    static String initialize(String value) { return "initialized:" + helper(value); }
    static String helper(String value) { return value.trim(); }
    @dex2c(mode = ProtectionMode.NATIVE, integrityRecheck = true)
    static String commit(String value) { return "committed:" + value; }
    @dex2c(integrityRecheck = false)
    static int hot(int value) { return value * 3 + 1; }
    public static void main(String[] args) {
        System.out.println(initialize(" cold "));
        System.out.println(commit("cold"));
        System.out.println(hot(7));
        System.out.println(initialize(" warm "));
        System.out.println(commit("warm"));
    }
}
