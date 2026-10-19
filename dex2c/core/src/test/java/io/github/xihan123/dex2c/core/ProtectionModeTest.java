package io.github.xihan123.dex2c.core;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.tree.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.objectweb.asm.Opcodes.*;

class ProtectionModeTest {
    private static AnnotationNode annotation(String value) {
        var a = new AnnotationNode(Selector.ANNOTATION);
        if (value != null) a.values = new ArrayList<>(List.of("mode", new String[]{"Lio/github/xihan123/dex2c/annotation/ProtectionMode;", value}));
        return a;
    }
    private static ClassNode type(String name, String parent) {
        var node = new ClassNode(); node.name = name; node.superName = parent; node.version = V17;
        return node;
    }
    private static MethodNode method(ClassNode c, String name, String mode) {
        var method = new MethodNode(ACC_PUBLIC, name, "()V", null, null);
        method.instructions.add(new InsnNode(RETURN));
        if (mode != null) method.invisibleAnnotations = new ArrayList<>(List.of(annotation(mode)));
        c.methods.add(method); return method;
    }
    @Test void methodThenInheritedThenClassThenGenerated() {
        ClassNode root = type("Root", "java/lang/Object"), child = type("Child", "Root");
        method(root, "entry", null); method(child, "entry", "NATIVE");
        child.invisibleAnnotations = new ArrayList<>(List.of(annotation("VMP")));
        method(child, "hot", "NATIVE"); method(child, "sensitive", null);
        var selector = new Selector(Map.of(root.name, root, child.name, child));
        selector.run(Set.of("Root#entry()V"));
        assertEquals(Selector.Policy.NATIVE_TREE, selector.policies.get(new MethodKey("Child", "entry", "()V")));
        assertEquals("method annotation", selector.selected.get(new MethodKey("Child", "entry", "()V")));
        assertEquals(Selector.Policy.NATIVE_TREE, selector.policies.get(new MethodKey("Child", "hot", "()V")));
        assertEquals(Selector.Policy.VMP_TREE, selector.policies.get(new MethodKey("Child", "sensitive", "()V")));
        child.invisibleAnnotations = new ArrayList<>(List.of(annotation("NATIVE")));
        child.methods.getFirst().invisibleAnnotations = null;
        selector = new Selector(Map.of(root.name, root, child.name, child)); selector.run(Set.of("Root#entry()V"));
        assertEquals(Selector.Policy.VMP_ENTRY, selector.policies.get(new MethodKey("Child", "entry", "()V")));
        assertTrue(selector.selected.get(new MethodKey("Child", "entry", "()V")).startsWith("inherited "));
    }
    @Test void legacyDefaultAndInvalidMode() {
        ClassNode c = type("Legacy", "java/lang/Object");
        var m = method(c, "run", null); m.invisibleAnnotations = new ArrayList<>(List.of(annotation(null)));
        var selector = new Selector(Map.of(c.name, c)); selector.run();
        assertEquals(Selector.Policy.VMP_TREE, selector.policies.get(new MethodKey(c.name, "run", "()V")));
        m.invisibleAnnotations = new ArrayList<>(List.of(annotation("UNKNOWN")));
        assertThrows(IllegalArgumentException.class, () -> new Selector(Map.of(c.name, c)).run());
    }
}
