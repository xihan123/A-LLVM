package io.github.xihan123.dex2c.sample.shared

import io.github.libxposed.api.XposedInterface
import io.github.xihan123.dex2c.annotation.dex2c
import java.lang.reflect.Method
import java.util.IdentityHashMap

@dex2c
object HookImplementation {
    private val installed = IdentityHashMap<ClassLoader, List<XposedInterface.HookHandle>>()

    @Synchronized
    fun install(api: XposedInterface, hostLoader: ClassLoader) {
        if (installed.containsKey(hostLoader)) return
        val target = Class.forName("io.github.xihan123.dex2c.sample.host.Probe", false, hostLoader)
        val calculate = target.getDeclaredMethod("calculate", Int::class.javaPrimitiveType)
        val throwing = target.getDeclaredMethod("throwing", Boolean::class.javaPrimitiveType)
        val handles = mutableListOf<XposedInterface.HookHandle>()
        runCatching {
            handles += calculate.around(api) { chain ->
                val args = chain.args.toTypedArray()
                args[0] = (args[0] as Int) + 7
                (chain.proceed(args) as Int) + 13
            }
            handles += throwing.around(api) { chain ->
                runCatching { chain.proceed(chain.args.toTypedArray()) }.getOrElse { -99 }
            }
            installed[hostLoader] = handles
        }.onFailure { error ->
            handles.forEach { it.unhook() }
            throw error
        }
    }

    private fun Method.around(api: XposedInterface, callback: (XposedInterface.Chain) -> Any?): XposedInterface.HookHandle =
        api.hook(this).intercept(XposedInterface.Hooker { chain -> callback(chain) })
}
