package io.github.xihan123.dex2c.sample.host;

public class MainActivity extends android.app.Activity {
    @Override public void onCreate(android.os.Bundle state) {
        super.onCreate(state);
        String result=Probe.run();
        android.util.Log.i("dex2c-sample",result);
        android.widget.TextView view=new android.widget.TextView(this);view.setText(result);setContentView(view);
        startService(new android.content.Intent(this,WorkerService.class));
    }
}
