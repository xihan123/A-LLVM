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
    enum Policy { NATIVE_TREE, VMP_ENTRY, VMP_TREE }
    final SortedMap<MethodKey, Policy> policies = new TreeMap<>();
    final SortedMap<String, MethodKey> inherited = new TreeMap<>();
    private final Map<MethodKey, Integer> priority = new HashMap<>();
    private final Map<String, Set<String>> inline = new HashMap<>();

    Selector(Map<String, ClassNode> classes) { this.classes = classes; }

    void run() { run(Set.of()); }

    void run(Set<String> inheritedMethods) {
        for (ClassNode owner : classes.values()) {
            boolean all = marked(owner.visibleAnnotations, owner.invisibleAnnotations);
            for (MethodNode method : owner.methods) {
                boolean explicit = marked(method.visibleAnnotations, method.invisibleAnnotations);
                if (all || explicit) {
                    AnnotationNode annotation = explicit ? selection(method.visibleAnnotations, method.invisibleAnnotations)
                            : selection(owner.visibleAnnotations, owner.invisibleAnnotations);
                    add(owner, method, explicit ? "method annotation" : "class annotation", explicit,
                            mode(annotation), explicit ? 4 : 2);
                }
            }
        }
        selectInherited(inheritedMethods);
        Map<MethodKey, Policy> visited = new HashMap<>();
        while (!visited.equals(policies)) {
            for (MethodKey key : List.copyOf(selected.keySet())) {
                Policy policy = policies.get(key);
                if (visited.put(key, policy) == policy) continue;
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
                                if (body != null && !body.name.startsWith("<")
                                        && (policy != Policy.VMP_TREE || (body.access & ACC_SYNTHETIC) != 0 || KotlinInfo.lambdaImplementation(target, body)))
                                    add(target, body, "callback of " + key, true, callbackPolicy(key));
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
                        boolean legacyHelper = (helper != null && (helper.access & ACC_SYNTHETIC) != 0)
                                && (target.name.equals(key.owner()) || target.name.startsWith(key.owner() + "$"));
                        boolean inheritedHelper = policy != Policy.VMP_TREE
                                && topLevel(target.name).equals(topLevel(key.owner()));
                        if (helper != null && !helper.name.startsWith("<") && (legacyHelper || inheritedHelper))
                            add(target, helper, "helper of " + key, true, policy);
                    }
                }
            }
        }
    }

    private void selectInherited(Set<String> requests) {
        for (String request : new TreeSet<>(requests)) {
            int separator = request.indexOf('#'), descriptor = request.indexOf('(', separator + 1);
            if (separator < 1 || descriptor <= separator + 1)
                throw new IllegalArgumentException("dex2c: expected class#method(descriptor): " + request);
            String root = request.substring(0, separator).replace('.', '/');
            String name = request.substring(separator + 1, descriptor), desc = request.substring(descriptor);
            ClassNode rootClass = classes.get(root);
            MethodNode declaration = rootClass == null ? null : find(rootClass, name, desc);
            if (declaration == null || (rootClass.access & ACC_INTERFACE) != 0 || name.startsWith("<") || (declaration.access & (ACC_STATIC | ACC_PRIVATE)) != 0)
                throw new IllegalArgumentException("dex2c: inherited root must declare an instance method: " + request);
            int matches = 0;
            for (ClassNode concrete : classes.values()) {
                if ((concrete.access & (ACC_ABSTRACT | ACC_INTERFACE)) != 0) continue;
                List<ClassNode> hierarchy = new ArrayList<>();
                Set<String> seen = new HashSet<>();
                for (ClassNode node = concrete; node != null; node = classes.get(node.superName)) {
                    if (!seen.add(node.name)) throw new IllegalArgumentException("dex2c: cyclic class hierarchy: " + concrete.name);
                    hierarchy.add(node);
                }
                if (hierarchy.stream().noneMatch(node -> node.name.equals(root))) continue;
                for (ClassNode owner : hierarchy) {
                    MethodNode implementation = find(owner, name, desc);
                    if (implementation == null) continue;
                    if ((implementation.access & (ACC_ABSTRACT | ACC_STATIC | ACC_PRIVATE | ACC_NATIVE)) != 0)
                        throw new IllegalArgumentException("dex2c: invalid inherited implementation: " + concrete.name + "#" + name + desc);
                    add(owner, implementation, "inherited " + request + " via " + concrete.name, true, Policy.VMP_ENTRY, 3);
                    inherited.put(concrete.name + "#" + name + desc, new MethodKey(owner.name, name, desc));
                    matches++;
                    break;
                }
            }
            if (matches == 0) throw new IllegalArgumentException("dex2c: inherited root matched no concrete classes: " + request);
        }
    }

    private Policy callbackPolicy(MethodKey key) {
        return policies.get(key) == Policy.VMP_TREE ? Policy.VMP_TREE : Policy.NATIVE_TREE;
    }

    private static String topLevel(String name) {
        int end = name.indexOf('$');
        return end < 0 ? name : name.substring(0, end);
    }

    private static boolean generated(ClassNode node) {
        return (node.access & ACC_SYNTHETIC) != 0 || node.outerMethod != null
                || node.innerClasses.stream().anyMatch(i -> i.name.equals(node.name) && i.innerName == null);
    }
    private void addGeneratedClass(ClassNode owner, MethodKey origin) {
        for (MethodNode method : owner.methods) add(owner, method, "generated callback of " + origin, false, callbackPolicy(origin));
    }
    private void add(ClassNode owner, MethodNode method, String reason, boolean explicit) {
        add(owner, method, reason, explicit, Policy.VMP_TREE);
    }
    private void add(ClassNode owner, MethodNode method, String reason, boolean explicit, Policy policy) {
        add(owner, method, reason, explicit, policy, 1);
    }
    private void add(ClassNode owner, MethodNode method, String reason, boolean explicit, Policy policy, int rank) {
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
        int previousRank = priority.getOrDefault(key, 0);
        if (rank > previousRank) {
            selected.put(key, reason);
            policies.put(key, policy); priority.put(key, rank);
        } else if (rank == previousRank) {
            selected.merge(key, reason, (previous, added) -> previous.contains(added) ? previous : previous + "; " + added);
            policies.merge(key, policy, (previous, added) -> previous.ordinal() >= added.ordinal() ? previous : added);
        }
    }
    MethodNode method(MethodKey key) { return Objects.requireNonNull(find(classes.get(key.owner()), key.name(), key.descriptor())); }
    static MethodNode find(ClassNode owner, String name, String descriptor) {
        return owner.methods.stream().filter(m -> m.name.equals(name) && m.desc.equals(descriptor)).findFirst().orElse(null);
    }
    static AnnotationNode annotation(List<AnnotationNode> nodes, String name) {
        return nodes == null ? null : nodes.stream().filter(a -> a.desc.equals(name)).findFirst().orElse(null);
    }
    private static boolean marked(List<AnnotationNode> visible, List<AnnotationNode> invisible) {
        return selection(visible, invisible) != null;
    }
    private static AnnotationNode selection(List<AnnotationNode> visible, List<AnnotationNode> invisible) {
        AnnotationNode node = annotation(visible, ANNOTATION);
        return node != null ? node : annotation(invisible, ANNOTATION);
    }
    private static Policy mode(AnnotationNode node) {
        if (node.values != null && node.values.size() % 2 != 0)
            throw new IllegalArgumentException("dex2c: malformed protection annotation");
        if (node.values != null) for (int i = 0; i < node.values.size(); i += 2) {
            if (!node.values.get(i).equals("mode")) continue;
            Object value = node.values.get(i + 1);
            if (!(value instanceof String[] pair) || pair.length != 2 ||
                    !pair[0].equals("Lio/github/xihan123/dex2c/annotation/ProtectionMode;"))
                throw new IllegalArgumentException("dex2c: invalid protection mode");
            return switch (pair[1]) {
                case "VMP" -> Policy.VMP_TREE;
                case "NATIVE" -> Policy.NATIVE_TREE;
                default -> throw new IllegalArgumentException("dex2c: unknown protection mode " + pair[1]);
            };
        }
        return Policy.VMP_TREE;
    }
    static IllegalArgumentException error(MethodKey key, String message) {
        return new IllegalArgumentException("dex2c: " + key + ": " + message);
    }
}
