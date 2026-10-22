package sample;

import io.github.xihan123.dex2c.annotation.dex2c;
import io.github.xihan123.dex2c.annotation.ProtectionMode;
import java.util.concurrent.*;

public class Run {
    public static final String PUBLIC_CONSTANT = "retained-public-field";
    public static String secret() { return "native-only-marker-42f35a63"; }
    @dex2c(mode = ProtectionMode.NATIVE)
    public static String converted() { return "whole-method-marker-9d8a"; }
    static final class Init {
        static String field = "initializer-marker-a9";
        final String value;
        Init() { value = "constructor-marker-b1"; }
    }
    interface Default {
        default String text() { return "interface-marker-c2"; }
    }
    private static void require(boolean condition) { if (!condition) throw new AssertionError(); }
    public static void main(String[] args) throws Exception {
        // The two entry orders exercise JNI_OnLoad without initializing business classes there.
        if (args.length > 0) require(converted().length() == 24);
        String expected = new String(new char[]{'n','a','t','i','v','e','-','o','n','l','y','-','m','a','r','k','e','r','-','4','2','f','3','5','a','6','3'});
        require(secret().equals(expected));
        require(secret() == expected.intern());
        require(converted().length() == 24);
        require("".length() == 0);
        String units = "A\0\uD83D\uDE03\uD800X\uDC01Z";
        require(units.equals(new String(new char[]{65,0,0xd83d,0xde03,0xd800,88,0xdc01,90})));
        require(new Init().value.length() == 21 && Init.field.length() == 21);
        require(new Default() {}.text().length() == 19);
        Callable<String> lambda = () -> "lambda-marker-d3";
        require(lambda.call().length() == 16);
        StringBuilder order = new StringBuilder();
        Object item = new Object() { public String toString() { order.append('a'); return "object-value"; } };
        String concat = "concat-prefix-" + item + ':' + 17 + "-suffix";
        require(concat.length() == 36 && order.toString().equals("a"));
        ExecutorService threads = Executors.newFixedThreadPool(8);
        try {
            java.util.List<Future<String>> values = new java.util.ArrayList<>();
            for (int i=0;i<32;i++) values.add(threads.submit(() -> "concurrent-first-marker"));
            String first = values.get(0).get();
            for (Future<String> value : values) require(value.get() == first);
        } finally { threads.shutdown(); }
        System.out.println(42);
    }
}
