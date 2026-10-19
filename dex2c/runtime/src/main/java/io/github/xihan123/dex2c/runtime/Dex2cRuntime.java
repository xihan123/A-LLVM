package io.github.xihan123.dex2c.runtime;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.ConcurrentHashMap;

/** 每个模块 ClassLoader 独立加载和注册；不主动初始化业务类。 */
public final class Dex2cRuntime {
    private static final Set<String> LIBRARIES = new HashSet<>();
    private static final Map<Class<?>, Binding> REGISTERED = new HashMap<>();

    private static final class Binding {
        final String library;
        final Method resolver;
        final Map<String, Class<?>> types = new ConcurrentHashMap<>();
        final Map<String, String> descriptors = new ConcurrentHashMap<>();
        Binding(String library, Method resolver) { this.library = library; this.resolver = resolver; }
    }

    private Dex2cRuntime() {}

    public static synchronized void ensureRegistered(Class<?> owner, String library, String resolverName) {
        Binding previous = REGISTERED.get(owner);
        if (previous != null) {
            if (!previous.library.equals(library)) throw new LinkageError("dex2c: conflicting library for " + owner.getName());
            return;
        }
        if (!LIBRARIES.contains(library)) {
            System.loadLibrary(library);
            LIBRARIES.add(library);
        }
        try {
            Method resolver = owner.getDeclaredMethod(resolverName, int.class);
            resolver.setAccessible(true);
            REGISTERED.put(owner, new Binding(library, resolver));
            registerClass(owner);
        } catch (ReflectiveOperationException e) {
            REGISTERED.remove(owner);
            throw new LinkageError("dex2c: missing type resolver for " + library, e);
        } catch (Error e) {
            REGISTERED.remove(owner);
            throw e;
        }
    }

    public static Class<?> resolveClass(Class<?> owner, String name, boolean initialize) throws Throwable {
        Binding binding;
        synchronized (Dex2cRuntime.class) { binding = REGISTERED.get(owner); }
        if (binding == null) throw new LinkageError("dex2c: class not registered: " + owner.getName());
        Class<?> type = binding.types.get(name);
        if (type == null) {
            if (name.startsWith("[")) {
                type = Class.forName(resolveDescriptor(owner, name).replace('/', '.'), false, owner.getClassLoader());
            } else {
                try { type = (Class<?>) binding.resolver.invoke(null, typeIndex(name)); }
                catch (InvocationTargetException e) { throw e.getCause(); }
                if (type == null) type = Class.forName(name.replace('/', '.'), false, owner.getClassLoader());
            }
            binding.types.put(name, type);
        }
        if (initialize) Class.forName(type.getName(), true, type.getClassLoader());
        return type;
    }

    public static String resolveDescriptor(Class<?> owner, String descriptor) throws Throwable {
        Binding binding;
        synchronized (Dex2cRuntime.class) { binding = REGISTERED.get(owner); }
        if (binding == null) throw new LinkageError("dex2c: class not registered: " + owner.getName());
        String cached = binding.descriptors.get(descriptor);
        if (cached != null) return cached;
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < descriptor.length(); i++) {
            char c = descriptor.charAt(i);
            result.append(c);
            if (c == 'L') {
                int end = descriptor.indexOf(';', i);
                if (end < 0) throw new LinkageError("dex2c: invalid descriptor: " + descriptor);
                result.append(resolveClass(owner, descriptor.substring(i + 1, end), false).getName().replace('.', '/'));
                result.append(';');
                i = end;
            }
        }
        String actual = result.toString();
        binding.descriptors.put(descriptor, actual);
        return actual;
    }

    private static native void registerClass(Class<?> owner);
    private static native int typeIndex(String name);
}
