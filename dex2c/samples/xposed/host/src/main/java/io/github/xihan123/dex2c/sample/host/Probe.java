package io.github.xihan123.dex2c.sample.host;

public final class Probe {
    public static int calculate(int input) { return input * 2; }
    public static int throwing(boolean fail) { if (fail) throw new IllegalStateException("expected"); return 7; }
    static String run() {
        int result=calculate(5);
        int error;
        try { error=throwing(true); } catch(IllegalStateException expected) { error=-1; }
        return "pid="+android.os.Process.myPid()+" calculate="+result+" exception="+error+" expected-with-module=37,-99";
    }
}
