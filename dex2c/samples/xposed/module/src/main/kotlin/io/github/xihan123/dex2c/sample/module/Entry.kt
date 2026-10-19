package io.github.xihan123.dex2c.sample.module

import android.util.Log
import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam
import io.github.xihan123.dex2c.sample.shared.HookImplementation

class Entry : XposedModule() {
    override fun onPackageReady(param: PackageReadyParam) {
        if (param.packageName != "io.github.xihan123.dex2c.sample.host") return
        runCatching {
            ExistingNative.check()
            HookImplementation.install(this, param.classLoader)
            HookImplementation.install(this, param.classLoader)
            val isolated = dalvik.system.PathClassLoader(param.applicationInfo.sourceDir, param.classLoader.parent)
            HookImplementation.install(this, isolated)
            HookImplementation.install(this, isolated)
            val probe = Class.forName("io.github.xihan123.dex2c.sample.host.Probe", false, isolated)
            check(probe.classLoader !== param.classLoader)
            check(probe.getDeclaredMethod("calculate", Int::class.javaPrimitiveType).invoke(null, 5) == 37)
            check(probe.getDeclaredMethod("throwing", Boolean::class.javaPrimitiveType).invoke(null, true) == -99)
            Log.i("dex2c-sample", "isolated-loader=OK existing-native=102 pid=${android.os.Process.myPid()}")
        }.onFailure {
            Log.e("dex2c-sample", "Hook initialization failed", it)
        }
    }
}
