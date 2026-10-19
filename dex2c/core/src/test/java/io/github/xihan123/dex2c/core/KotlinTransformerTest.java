package io.github.xihan123.dex2c.core;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class KotlinTransformerTest {
    @TempDir Path temp;
    private Path input() throws Exception {return Path.of(kfixture.Fixture.class.getProtectionDomain().getCodeSource().getLocation().toURI());}
    @Test void kotlinCallbacksAndContinuationsAreSelected() throws Exception {
        var result=new Transformer().transform(List.of(input()),temp.resolve("generated"),"dex2c_kotlin");
        assertTrue(result.methods().stream().anyMatch(m->m.name().equals("invokeSuspend")));
        assertTrue(result.methods().stream().anyMatch(m->m.name().equals("resumeWith")));
        assertTrue(result.methods().stream().anyMatch(m->m.name().equals("run")&&m.owner().contains("anonymous")));
    }
    @Test void metadataRejectsInlineFunctionsAndAccessors() throws Exception {
        ClassNode node=new ClassNode();
        try(InputStream stream=kfixture.InlineBoundary.class.getResourceAsStream("/kfixture/InlineBoundary.class")) {
            new ClassReader(Objects.requireNonNull(stream)).accept(node,0);
        }
        Set<String> methods=KotlinInfo.inlineMethods(node);
        assertTrue(methods.contains("kind()Ljava/lang/Class;"));assertTrue(methods.contains("getAnswer()I"));
        node.invisibleAnnotations=new ArrayList<>(List.of(new AnnotationNode(Selector.ANNOTATION)));
        Selector selector=new Selector(Map.of(node.name,node));
        assertThrows(IllegalArgumentException.class,selector::run);
    }
    @Test void kotlinNativeMatchesJvm() throws Exception {
        String compiler=System.getProperty("dex2c.hostCompiler","");
        Assumptions.assumeFalse(compiler.isBlank());
        var result=new Transformer().transform(List.of(input()),temp.resolve("generated"),"dex2c_kotlin");
        boolean windows=System.getProperty("os.name").startsWith("Windows");Path jdk=Path.of(System.getProperty("java.home"));
        run(List.of(compiler,"--driver-mode=g++","-std=gnu++17","-shared","-fno-exceptions","-I"+jdk.resolve("include"),
                "-I"+jdk.resolve("include").resolve(windows?"win32":"linux"),result.nativeSource().toString(),result.registration().toString(),
                result.nativeSource().resolveSibling("dex2c_runtime.cpp").toString(),"-o",temp.resolve(windows?"dex2c_kotlin.dll":"libdex2c_kotlin.so").toString()));
        String java=jdk.resolve("bin").resolve(windows?"java.exe":"java").toString();
        String original=run(List.of(java,"-Xcheck:jni","-cp",System.getProperty("java.class.path"),"kfixture.FixtureKt"));
        String converted=run(List.of(java,"-Xcheck:jni","-Djava.library.path="+temp,"-cp",result.classes()+File.pathSeparator+System.getProperty("java.class.path"),"kfixture.FixtureKt"));
        assertEquals(original,converted);
    }
    @Test void generatedKotlinCompilesToVerifiedArm64Vmp() throws Exception {
        String ndk=System.getProperty("dex2c.ndk","");String compiler=System.getProperty("dex2c.hostCompiler","");
        Assumptions.assumeFalse(ndk.isBlank()||compiler.isBlank());
        Path generated=temp.resolve("generated");
        var result=new Transformer().transform(List.of(input()),generated,"dex2c_kotlin");
        new NativeCompiler().compile(generated,temp.resolve("native"),Path.of(ndk),Path.of(compiler),"dex2c_kotlin",26,
                TestSigning.certificate(temp),TestSigning.python());
        String report=Files.readString(temp.resolve("native/protection.json"));
        assertTrue(report.contains("\"protectedMethods\":"+result.methods().size()));
    }
    private String run(List<String> command) throws Exception {
        Process process=new ProcessBuilder(command).redirectErrorStream(true).start();
        String text=new String(process.getInputStream().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(0,process.waitFor(),text.substring(0,Math.min(text.length(),5000)));
        return text.replace("\r\n","\n");
    }
}
