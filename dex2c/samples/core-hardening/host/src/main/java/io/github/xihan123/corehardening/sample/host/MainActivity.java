package io.github.xihan123.corehardening.sample.host;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class MainActivity extends Activity {
    private TextView result;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int padding = (int) (24 * getResources().getDisplayMetrics().density);
        layout.setPadding(padding, padding, padding, padding);

        result = new TextView(this);
        result.setText("Running protected arithmetic checks...");
        layout.addView(result);

        Button rerun = new Button(this);
        rerun.setText("Run checks");
        rerun.setOnClickListener(view -> runChecks());
        layout.addView(rerun);
        setContentView(layout);

        runChecks();
    }

    private void runChecks() {
        result.setText("Running protected arithmetic checks...");
        new Thread(() -> {
            String summary = Validation.run("main");
            runOnUiThread(() -> result.setText(summary));
            startService(new Intent(this, WorkerService.class));
        }, "core-hardening-main-check").start();
    }
}
