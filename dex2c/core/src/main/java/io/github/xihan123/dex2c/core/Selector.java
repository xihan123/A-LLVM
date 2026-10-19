package io.github.xihan123.dex2c.core;

import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import java.util.*;
import static org.objectweb.asm.Opcodes.*;

final class Selector {
    static final String ANNOTATION = "Lio/github/xihan123/dex2c/annotation/dex2c;";
    final Map<String, ClassNode> classes;
    final SortedMap<MethodKey, String> selected = new TreeMap<>();
    final SortedMap<MethodKey, String> excluded = new TreeMap<>();
    private final Map<String, Set<String>> inline = new HashMap<>();

    Selector(Map<String, ClassNode> classes) { this.classes = classes; }

    void run() {
        for (ClassNode owner : classes.values()) {
            boolean all = marked(owner.visibleAnnotations, owner.invisibleAnnotations);
            for (MethodNode method : owner.methods) {
                boolean explicit = marked(method.visibleAnnotations, method.invisibleAnnotations);
                if (all || explicit) add(owner, method, explicit ? "method annotation" : "class annotation", explicit);
            }
        }
        Set<MethodKey> visited = new HashSet<>();
        while (visited.size() < selected.size()) {
            for (MethodKey key : List.copyOf(selected.keySet())) {
                if (!visited.add(key)) continue;
                MethodNode method = method(key);
                for (ClassNode enclosed : classes.values()) {
                    if (key.owner().equals(enclosed.outerClass) && key.name().equals(enclosed.outerMethod)
                            && (enclosed.outerMethodDesc == null || key.descriptor().equals(enclosed.outerMethodDesc)))
                        addGeneratedClass(enclosed, key);
                }
                for (AbstractInsnNode instruction : method.instructions) {
                    if (instruction instanceof InvokeDynamicInsnNode indy) {
                        if (indy.bsm.getOwner().equals("java/lang/invoke/LambdaMetafactory")) {
                            if (!(indy.bsmArgs.length > 1 && indy.bsmArgs[1] instanceof Handle handle))
                                throw error(key, "malformed LambdaMetafactory call");
                            ClassNode target = classes.get(handle.getOwner());
                            if (target != null) {
                                MethodNode body = find(target, handle.getName(), handle.getDesc());
                                if (body != null && (body.access & ACC_SYNTHETIC) != 0 && !body.name.startsWith("<"))
                                    add(target, body, "callback of " + key, true);
                            }
                        } else if (!indy.bsm.getOwner().equals("java/lang/invoke/StringConcatFactory")) {
                            throw error(key, "unsupported invokedynamic bootstrap " + indy.bsm.getOwner());
                        }
                    }
                    String reference = instruction instanceof TypeInsnNode t ? t.desc
                            : instruction instanceof FieldInsnNode f ? f.owner : null;
                    if (reference != null && classes.containsKey(reference)) {
                        ClassNode target = classes.get(reference);
                        if (target.name.startsWith(key.owner() + "$") && generated(target)) {
                            if (target.outerMethod == null && target.outerClass == null)
                                throw error(key, "cannot establish generated class ownership: " + reference);
                            addGeneratedClass(target, key);
                        }
                    }
                    if (instruction instanceof MethodInsnNode call && classes.containsKey(call.owner)) {
                        ClassNode target = classes.get(call.owner);
                        MethodNode helper = find(target, call.name, call.desc);
                        if (helper != null && (helper.access & ACC_SYNTHETIC) != 0 && !helper.name.startsWith("<")
                                && (target.name.equals(key.owner()) || target.name.startsWith(key.owner() + "$")))
                            add(target, helper, "generated helper of " + key, true);
                    }
                }
            }
        }
    }

    private static boolean generated(ClassNode node) {
        return (node.access & ACC_SYNTHETIC) != 0 || node.outerMethod != null
                || node.innerClasses.stream().anyMatch(i -> i.name.equals(node.name) && i.innerName == null);
    }
    private void addGeneratedClass(ClassNode owner, MethodKey origin) {
        for (MethodNode method : owner.methods) add(owner, method, "generated callback of " + origin, false);
    }
    private void add(ClassNode owner, MethodNode method, String reason, boolean explicit) {
        MethodKey key = new MethodKey(owner.name, method.name, method.desc);
        String exclusion = method.name.startsWith("<") ? "constructor or class initializer"
                : (method.access & ACC_ABSTRACT) != 0 ? "abstract method"
                : (method.access & ACC_NATIVE) != 0 ? "existing native method" : null;
        if (exclusion != null) {
            if (explicit) throw error(key, exclusion + " cannot be annotated");
            excluded.put(key, exclusion);
            return;
        }
        if (inline.computeIfAbsent(owner.name, n -> KotlinInfo.inlineMethods(owner)).contains(method.name + method.desc))
            throw error(key, "Kotlin inline/reified methods may already have unprotected copies at call sites");
        selected.merge(key, reason, (previous, added) -> previous.contains(added) ? previous : previous + "; " + added);
    }
    MethodNode method(MethodKey key) { return Objects.requireNonNull(find(classes.get(key.owner()), key.name(), key.descriptor())); }
    static MethodNode find(ClassNode owner, String name, String descriptor) {
        return owner.methods.stream().filter(m -> m.name.equals(name) && m.desc.equals(descriptor)).findFirst().orElse(null);
    }
    static AnnotationNode annotation(List<AnnotationNode> nodes, String name) {
        return nodes == null ? null : nodes.stream().filter(a -> a.desc.equals(name)).findFirst().orElse(null);
    }
    private static boolean marked(List<AnnotationNode> visible, List<AnnotationNode> invisible) {
        return annotation(visible, ANNOTATION) != null || annotation(invisible, ANNOTATION) != null;
    }
    static IllegalArgumentException error(MethodKey key, String message) {
        return new IllegalArgumentException("dex2c: " + key + ": " + message);
    }
}
