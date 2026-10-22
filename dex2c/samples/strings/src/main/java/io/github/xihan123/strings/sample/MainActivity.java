package io.github.xihan123.strings.sample;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import io.github.xihan123.dex2c.annotation.dex2c;
import io.github.xihan123.dex2c.annotation.ProtectionMode;

public final class MainActivity extends Activity {
    public static final String PUBLIC_CONSTANT = "retained-public-constant";
    static String message() { return "java-string-marker-d3d7cf46"; }
    @dex2c(mode = ProtectionMode.NATIVE)
    static String nativeMessage() { return "native-string-marker-538bf047"; }

    private static String value() { return message() + '\n' + Messages.message() + '\n' + nativeMessage(); }

    public static void main(String[] args) {
        String value = value();
        if (value.length() != 87) throw new AssertionError(value.length());
        System.out.println(value.length());
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView text = new TextView(this);
        String value = value();
        text.setText(value);
        setContentView(text);
        android.util.Log.i("StringsSample", "STRINGS_SAMPLE_OK:" + value.length());
    }
}
