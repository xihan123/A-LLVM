package io.github.xihan123.dex2c.core;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import javax.tools.ToolProvider;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.JarFile;
import static org.junit.jupiter.api.Assertions.*;

class TransformerTest {
    @TempDir Path temp;
    Path compileFixture() throws Exception {
        Path source=temp.resolve("Run.java");
        try(InputStream input=getClass().getResourceAsStream("/fixtures/Run.java")){Files.copy(Objects.requireNonNull(input),source);}
        Path classes=Files.createDirectories(temp.resolve("classes"));
        assertEquals(0,ToolProvider.getSystemJavaCompiler().run(null,null,null,"-g","-classpath",System.getProperty("java.class.path"),"-d",classes.toString(),source.toString()));
        return classes;
    }
    @Test void selectsCallbacksAndRemovesOriginalBodies() throws Exception {
        var result=new Transformer().transform(List.of(compileFixture()),temp.resolve("generated"),"dex2c_test");
        assertTrue(result.methods().stream().anyMatch(m->m.name().startsWith("lambda$")));
        assertTrue(result.methods().stream().anyMatch(m->m.owner().equals("sample/MethodOnly")&&m.name().equals("selected")));
        assertTrue(result.methods().stream().anyMatch(m->m.owner().equals("sample/MethodOnly")&&m.name().startsWith("lambda$")));
        assertFalse(result.methods().stream().anyMatch(m->m.name().equals("untouched")));
        assertTrue(result.methods().stream().anyMatch(m->m.owner().equals("sample/Logic$1")&&m.name().equals("run")));
        assertFalse(result.methods().stream().anyMatch(m->m.name().startsWith("<")));
        String report=Files.readString(result.report());assertTrue(report.contains("constructor or class initializer"));
        try(JarFile jar=new JarFile(result.classes().toFile())) {
            byte[] bytes=jar.getInputStream(jar.getJarEntry("sample/Logic.class")).readAllBytes();
            new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
                @Override public MethodVisitor visitMethod(int access,String name,String desc,String signature,String[] exceptions) {
                    if(name.equals("work"))return new MethodVisitor(Opcodes.ASM9){
                        @Override public void visitFieldInsn(int opcode,String owner,String name,String desc){fail("original field access remains in DEX bridge");}
                    };
                    return null;
                }
            },0);
        }
        assertTrue(Files.readString(result.nativeSource()).contains("d2c_catch"));
        assertTrue(Files.readString(result.rules()).contains("sample.Parent"));
    }
    @Test void nativeAndJvmSemanticsMatchWithCheckJni() throws Exception {
        String compiler=System.getProperty("dex2c.hostCompiler","");
        Assumptions.assumeFalse(compiler.isBlank(),"set -Pdex2c.hostCompiler=<clang++> to run JNI differential tests");
        Path classes=compileFixture();
        var result=new Transformer().transform(List.of(classes),temp.resolve("generated"),"dex2c_test");
        boolean windows=System.getProperty("os.name").startsWith("Windows");
        Path jdk=Path.of(System.getProperty("java.home"));
        Path library=temp.resolve(windows?"dex2c_test.dll":"libdex2c_test.so");
        run(List.of(compiler,"--driver-mode=g++","-std=gnu++17","-shared","-fno-exceptions","-fno-fast-math","-ffp-contract=off",
                "-I"+jdk.resolve("include"),"-I"+jdk.resolve("include").resolve(windows?"win32":"linux"),
                result.nativeSource().toString(),result.registration().toString(),result.nativeSource().resolveSibling("dex2c_runtime.cpp").toString(),"-o",library.toString()));
        String java=jdk.resolve("bin").resolve(windows?"java.exe":"java").toString();
        String original=run(List.of(java,"-Xcheck:jni","-cp",classes+File.pathSeparator+System.getProperty("java.class.path"),"sample.Run"));
        String converted=run(List.of(java,"-Xcheck:jni","-Djava.library.path="+temp,"-cp",result.classes()+File.pathSeparator+System.getProperty("java.class.path"),"sample.Run"));
        assertEquals(original,converted,"JNI diagnostics or semantic differences");
    }
    @Test void artifactNamesAndNumericResolversAreCompleteAndDeterministic() throws Exception {
        Path input=compileFixture();
        var result=new Transformer().transform(List.of(input),temp.resolve("one"),"module");
        var repeated=new Transformer().transform(List.of(input),temp.resolve("two"),"module");
        assertArrayEquals(Files.readAllBytes(result.classes()),Files.readAllBytes(repeated.classes()));
        try(JarFile jar=new JarFile(result.classes().toFile())) {
            assertNull(jar.getJarEntry(RuntimeLayout.TEMPLATE+".class"));
            int resolvers=0;
            for(var entry:jar.stream().toList()) {
                ClassNode node=new ClassNode();new ClassReader(jar.getInputStream(entry)).accept(node,0);
                for(MethodNode method:node.methods) {
                    assertFalse(method.name.contains("__dex2c"));
                    if(method.invisibleAnnotations!=null)assertFalse(method.invisibleAnnotations.stream().anyMatch(a->a.desc.equals(Selector.ANNOTATION)));
                    if(!method.name.equals(RuntimeLayout.resolver(node.name)))continue;
                    resolvers++;
                    assertEquals("(I)Ljava/lang/Class;",method.desc);
                    assertTrue(Arrays.stream(method.instructions.toArray()).anyMatch(i->i instanceof LookupSwitchInsnNode));
                    assertFalse(Arrays.stream(method.instructions.toArray()).anyMatch(i->i instanceof LdcInsnNode l&&l.cst instanceof String));
                }
            }
            assertTrue(resolvers>1);
        }
        String nativeSource=Files.readString(result.registration());
        assertTrue(nativeSource.contains("JNI_OnLoad"));
        String types=Files.readString(result.registration().resolveSibling("dex2c_runtime.cpp"));
        assertTrue(types.contains("sample/Aa")&&types.contains("sample/BB"));
        assertFalse(nativeSource.contains("Java_io_github")||nativeSource.contains("__dex2c"));
    }
    @Test void explicitNativeAndConflictingClassInputsFail() throws Exception {
        ClassWriter writer=new ClassWriter(0);writer.visit(Opcodes.V17,Opcodes.ACC_PUBLIC,"Bad",null,"java/lang/Object",null);
        var method=writer.visitMethod(Opcodes.ACC_PUBLIC|Opcodes.ACC_NATIVE,"bad","()V",null,null);
        method.visitAnnotation(Selector.ANNOTATION,false).visitEnd();method.visitEnd();writer.visitEnd();
        Path input=Files.createDirectory(temp.resolve("input"));Files.write(input.resolve("Bad.class"),writer.toByteArray());
        var error=assertThrows(IllegalArgumentException.class,()->new Transformer().transform(List.of(input),temp.resolve("out"),"dex2c_test"));
        assertTrue(error.getMessage().contains("existing native method"));
    }
    private String run(List<String> arguments) throws Exception {
        Process process=new ProcessBuilder(arguments).redirectErrorStream(true).start();
        String output=new String(process.getInputStream().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(0,process.waitFor(),String.join(" ",arguments)+"\n"+output);
        return output.replace("\r\n","\n");
    }
}
