package io.github.xihan123.dex2c.core;

import kotlin.Metadata;
import kotlin.metadata.Attributes;
import kotlin.metadata.KmFunction;
import kotlin.metadata.jvm.JvmExtensionsKt;
import kotlin.metadata.jvm.KotlinClassMetadata;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.lang.reflect.Proxy;
import java.util.*;
import static org.objectweb.asm.Opcodes.*;

final class KotlinInfo {
    static Set<String> inlineMethods(ClassNode owner) {
        return methods(owner, true);
    }

    static boolean lambdaImplementation(ClassNode owner, MethodNode method) {
        // Kotlin 2.4 indy bodies are private static methods, without ACC_SYNTHETIC.
        // The implementation handle establishes the call edge; metadata separates
        // compiler bodies from source methods used as callable references.
        return method.name.contains("$lambda$")
                && (method.access & (ACC_PRIVATE | ACC_STATIC)) == (ACC_PRIVATE | ACC_STATIC)
                && Selector.annotation(owner.visibleAnnotations, "Lkotlin/Metadata;") != null
                && !methods(owner, false).contains(method.name + method.desc);
    }

    private static Set<String> methods(ClassNode owner, boolean inlineOnly) {
        AnnotationNode node = Selector.annotation(owner.visibleAnnotations, "Lkotlin/Metadata;");
        if (node == null) return Set.of();
        Map<String, Object> values = new HashMap<>();
        for (int i = 0; node.values != null && i < node.values.size(); i += 2)
            values.put((String) node.values.get(i), node.values.get(i + 1));
        Metadata header = (Metadata) Proxy.newProxyInstance(Metadata.class.getClassLoader(),
                new Class<?>[]{Metadata.class}, (proxy, method, args) -> {
                    if (method.getName().equals("annotationType")) return Metadata.class;
                    Object value = values.getOrDefault(method.getName(), method.getDefaultValue());
                    if (value instanceof List<?> list) {
                        if (method.getReturnType() == int[].class) return list.stream().mapToInt(v -> (Integer) v).toArray();
                        return list.toArray(String[]::new);
                    }
                    return value;
                });
        try {
            KotlinClassMetadata metadata = KotlinClassMetadata.readLenient(header);
            List<KmFunction> functions = switch (metadata) {
                case KotlinClassMetadata.Class c -> c.getKmClass().getFunctions();
                case KotlinClassMetadata.FileFacade f -> f.getKmPackage().getFunctions();
                case KotlinClassMetadata.MultiFileClassPart p -> p.getKmPackage().getFunctions();
                default -> List.of();
            };
            Set<String> result = new HashSet<>();
            for (KmFunction function : functions) {
                var signature = JvmExtensionsKt.getSignature(function);
                if ((!inlineOnly || Attributes.isInline(function)) && signature != null)
                    result.add(signature.getName() + signature.getDescriptor());
            }
            var properties = switch (metadata) {
                case KotlinClassMetadata.Class c -> c.getKmClass().getProperties();
                case KotlinClassMetadata.FileFacade f -> f.getKmPackage().getProperties();
                case KotlinClassMetadata.MultiFileClassPart p -> p.getKmPackage().getProperties();
                default -> List.<kotlin.metadata.KmProperty>of();
            };
            for (var property : properties) {
                var getter = JvmExtensionsKt.getGetterSignature(property);
                var setter = JvmExtensionsKt.getSetterSignature(property);
                if (getter != null && (!inlineOnly || Attributes.isInline(property.getGetter()))) result.add(getter.getName() + getter.getDescriptor());
                if (setter != null && property.getSetter() != null && (!inlineOnly || Attributes.isInline(property.getSetter()))) result.add(setter.getName() + setter.getDescriptor());
            }
            return result;
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("dex2c: cannot read Kotlin metadata for " + owner.name, e);
        }
    }
}
