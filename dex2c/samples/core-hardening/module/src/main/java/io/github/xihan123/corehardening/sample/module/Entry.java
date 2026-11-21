package io.github.xihan123.corehardening.sample.module;

import android.util.Log;
import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam;

public final class Entry extends XposedModule {
    private static final String HOST_PACKAGE = "io.github.xihan123.corehardening.sample.host";
    private static final String TAG = "core-hardening";

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!HOST_PACKAGE.equals(param.getPackageName())) {
            return;
        }
        try {
            Class<?> probe = Class.forName(HOST_PACKAGE + ".Probe", false, param.getClassLoader());
            hook(probe.getDeclaredMethod("calculate", int.class, int.class, int.class),
                    args -> ProtectedArithmetic.calculate((int) args[0], (int) args[1], (int) args[2]));
            hook(probe.getDeclaredMethod("nativeCalculate", int.class, int.class, int.class),
                    args -> NativeFusion.calculate((int) args[0], (int) args[1], (int) args[2]));
            hook(probe.getDeclaredMethod("accumulate", long.class, int.class),
                    args -> ProtectedArithmetic.accumulate((long) args[0], (int) args[1]));
            Log.i(TAG, "hooks-installed package=" + param.getPackageName()
                    + " pid=" + android.os.Process.myPid());
        } catch (Throwable error) {
            Log.e(TAG, "hook installation failed package=" + param.getPackageName(), error);
        }
    }

    private void hook(java.lang.reflect.Method method, ProtectedCall call) {
        hook(method).setExceptionMode(XposedInterface.ExceptionMode.PASSTHROUGH)
                .intercept(new XposedInterface.Hooker() {
            @Override
            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                return call.invoke(chain.getArgs().toArray());
            }
        });
    }

    private interface ProtectedCall {
        Object invoke(Object[] args) throws Throwable;
    }
}
