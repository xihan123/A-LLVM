package io.github.xihan123.corehardening.sample.host;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

public final class WorkerService extends Service {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        new Thread(() -> {
            Validation.run("worker");
            stopSelf(startId);
        }, "core-hardening-worker-check").start();
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
