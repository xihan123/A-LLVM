package io.github.xihan123.dex2c.sample.host;

public class WorkerService extends android.app.Service {
    @Override public int onStartCommand(android.content.Intent intent,int flags,int id) {
        android.util.Log.i("dex2c-sample",Probe.run());stopSelf(id);return START_NOT_STICKY;
    }
    @Override public android.os.IBinder onBind(android.content.Intent intent){return null;}
}
