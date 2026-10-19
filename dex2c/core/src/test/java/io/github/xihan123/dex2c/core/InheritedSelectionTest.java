package io.github.xihan123.dex2c.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import javax.tools.ToolProvider;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import static org.junit.jupiter.api.Assertions.*;

/** 继承根跨制品选择；保持注解语义与高频回调的原生执行策略。 */
class InheritedSelectionTest {
    @TempDir Path temp;

    private Path fixture() throws Exception {
        Path source = temp.resolve("Root.java"), classes = Files.createDirectory(temp.resolve("classes"));
        Files.writeString(source, """
                package inherited;
                import io.github.xihan123.dex2c.annotation.dex2c;
                import java.util.function.IntUnaryOperator;
                abstract class Root {
                    abstract int install(int value);
                    int install() { return 99; }
                    String unrelated() { return "not a hook"; }
                }
                abstract class Middle extends Root {
                    int install(int value) { IntUnaryOperator f = n -> n + 7; return f.applyAsInt(value); }
                }
                final class Leaf extends Middle {}
                final class Other extends Root {
                    int install(int value) { IntUnaryOperator f = this::named; return f.applyAsInt(value); }
                    private int named(int value) { return helper(value); }
                    private int helper(int value) { return value * 2; }
                }
                final class Explicit extends Root {
                    @dex2c int install(int value) { IntUnaryOperator f = n -> n - 3; return f.applyAsInt(value); }
                }
                """);
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, null, null,
                "-classpath", System.getProperty("java.class.path"), "-d", classes.toString(), source.toString()));
        return classes;
    }

    @Test void selectsActualImplementationsAcrossJarsAndSeparatesCallbacks() throws Exception {
        Path classes = fixture(), shared = temp.resolve("shared.jar"), app = temp.resolve("app.jar");
        try (var parent = new JarOutputStream(Files.newOutputStream(shared));
             var child = new JarOutputStream(Files.newOutputStream(app));
             var files = Files.walk(classes)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                var jar = file.getFileName().toString().equals("Root.class") ? parent : child;
                jar.putNextEntry(new JarEntry(classes.relativize(file).toString().replace('\\', '/')));
                jar.write(Files.readAllBytes(file)); jar.closeEntry();
            }
        }
        var result = new Transformer().transform(List.of(shared, app), temp.resolve("out"), "inherit",
                Set.of("inherited.Root#install(I)I"));
        assertTrue(result.methods().stream().anyMatch(k -> k.owner().equals("inherited/Middle") && k.name().equals("install")));
        assertFalse(result.methods().stream().anyMatch(k -> k.descriptor().equals("()I") || k.name().equals("unrelated")));
        String report = Files.readString(result.report());
        assertTrue(report.contains("inherited/Leaf#install(I)I\":\"inherited/Middle.install(I)I"));
        assertTrue(report.contains("inherited/Other#install(I)I"));
        assertTrue(report.contains("inherited/Explicit#install(I)I"));
        assertEquals(3, Files.readAllLines(temp.resolve("out/native-symbols.txt")).size());
        String nativeSource = Files.readString(temp.resolve("out/native.cpp"));
        String vmSource = Files.readString(result.nativeSource());
        var middleCallback = result.methods().stream().filter(k -> k.owner().equals("inherited/Middle") && k.name().startsWith("lambda$")).findFirst().orElseThrow();
        assertTrue(nativeSource.contains(middleCallback.symbol()));
        assertFalse(vmSource.contains(middleCallback.symbol()));
        for (String name : List.of("named", "helper")) {
            var named = result.methods().stream().filter(k -> k.owner().equals("inherited/Other") && k.name().equals(name)).findFirst().orElseThrow();
            assertTrue(nativeSource.contains(named.symbol()));
            assertFalse(vmSource.contains(named.symbol()));
        }
        var explicitCallback = result.methods().stream().filter(k -> k.owner().equals("inherited/Explicit") && k.name().startsWith("lambda$")).findFirst().orElseThrow();
        assertTrue(vmSource.contains(explicitCallback.symbol()), "existing annotations must retain VMP callbacks");
    }

    @Test void invalidRootsAndCyclesFailInsteadOfSilentlySelectingNothing() throws Exception {
        Path classes = fixture();
        for (String root : List.of("missing.Root#install(I)I", "inherited.Root#missing()V", "inherited.Root", "inherited.Root#<init>()V"))
            assertThrows(IllegalArgumentException.class, () -> new Transformer().transform(List.of(classes), temp.resolve("bad"), "inherit", Set.of(root)));
        Map<String, ClassNode> nodes = new TreeMap<>();
        try (var files = Files.walk(classes)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                var node = new ClassNode(); new ClassReader(Files.readAllBytes(file)).accept(node, 0); nodes.put(node.name, node);
            }
        }
        nodes.get("inherited/Middle").superName = "inherited/Leaf";
        assertThrows(IllegalArgumentException.class, () -> new Selector(nodes).run(Set.of("inherited.Root#install(I)I")));
    }

    @Test void nativeCallbacksRequireImplementationAndRejectPlaintextOrVm() {
        String symbol = "d2c_0123456789abcdef01234567";
        String ir = "define i32 @" + symbol + "() {\n ret i32 42\n}\n";
        assertDoesNotThrow(() -> NativeCompiler.verifyNativeIr(ir, List.of(symbol)));
        assertThrows(IllegalStateException.class, () -> NativeCompiler.verifyNativeIr("", List.of(symbol)));
        assertThrows(IllegalStateException.class, () -> NativeCompiler.verifyNativeIr(ir + "!ndkp.vmp.protected", List.of(symbol)));
        assertThrows(IllegalStateException.class, () -> NativeCompiler.verifyNativeIr(ir + "@.str = private constant [7 x i8] c\"secret\\00\"\n", List.of(symbol)));
    }

    @Test void inheritedMixedSourcesMatchJvmWithCheckJni() throws Exception {
        String compiler = System.getProperty("dex2c.hostCompiler", "");
        Assumptions.assumeFalse(compiler.isBlank(), "set -Pdex2c.hostCompiler to run JNI differential tests");
        Path classes = fixture(), runner = temp.resolve("Run.java");
        Files.writeString(runner, """
                package inherited;
                public class Run {
                    public static void main(String[] args) {
                        for (int n : new int[] {0, 1, -1, Integer.MAX_VALUE, Integer.MIN_VALUE})
                            System.out.println(new Leaf().install(n) + ":" + new Other().install(n) + ":" + new Explicit().install(n));
                    }
                }
                """);
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, null, null,
                "-classpath", classes + File.pathSeparator + System.getProperty("java.class.path"), "-d", classes.toString(), runner.toString()));
        var result = new Transformer().transform(List.of(classes), temp.resolve("mixed"), "inherit", Set.of("inherited.Root#install(I)I"));
        boolean windows = System.getProperty("os.name").startsWith("Windows");
        Path jdk = Path.of(System.getProperty("java.home"));
        run(List.of(compiler, "--driver-mode=g++", "-std=gnu++17", "-shared", "-fno-exceptions",
                "-I" + jdk.resolve("include"), "-I" + jdk.resolve("include").resolve(windows ? "win32" : "linux"),
                result.nativeSource().toString(), temp.resolve("mixed/native.cpp").toString(), result.registration().toString(),
                temp.resolve("mixed/dex2c_runtime.cpp").toString(), "-o", temp.resolve(windows ? "inherit.dll" : "libinherit.so").toString()));
        String java = jdk.resolve(windows ? "bin/java.exe" : "bin/java").toString();
        String original = run(List.of(java, "-Xcheck:jni", "-cp", classes + File.pathSeparator + System.getProperty("java.class.path"), "inherited.Run"));
        String converted = run(List.of(java, "-Xcheck:jni", "-Djava.library.path=" + temp, "-cp", result.classes() + File.pathSeparator + System.getProperty("java.class.path"), "inherited.Run"));
        assertEquals(original, converted);
    }

    private String run(List<String> arguments) throws Exception {
        Process process = new ProcessBuilder(arguments).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(0, process.waitFor(), output);
        return output.replace("\r\n", "\n");
    }
}
