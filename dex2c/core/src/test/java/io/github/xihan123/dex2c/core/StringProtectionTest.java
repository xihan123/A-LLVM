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

class StringProtectionTest {
    @TempDir Path temp;

    Path fixture() throws Exception {
        Path source=temp.resolve("Run.java"),classes=Files.createDirectories(temp.resolve("classes"));
        try(var input=getClass().getResourceAsStream("/fixtures/strings/Run.java")) {Files.copy(input,source);}
        assertEquals(0,ToolProvider.getSystemJavaCompiler().run(null,null,null,"-g","-cp",System.getProperty("java.class.path"),"-d",classes.toString(),source.toString()));
        return classes;
    }
    Transformer.Result transform(Path input,boolean combined) throws Exception {
        return new Transformer().transform(List.of(input),temp.resolve("generated"),"strings_test",Set.of(),combined,Set.of("sample"),Set.of());
    }
    @Test void extractsLiteralsConcatAndPreservesPublicMetadata() throws Exception {
        var result=transform(fixture(),false);
        assertTrue(result.methods().isEmpty());
        String report=Files.readString(temp.resolve("generated/string-selection.json"));
        assertTrue(report.contains("ConstantValue"));
        assertFalse(report.contains("native-only-marker-42f35a63"));
        try(JarFile jar=new JarFile(result.classes().toFile())) {
            for(var entry:jar.stream().toList()) {
                if(!entry.getName().startsWith("sample/"))continue;
                ClassNode node=new ClassNode();new ClassReader(jar.getInputStream(entry)).accept(node,0);
                for(var method:node.methods)for(var instruction:method.instructions) {
                    assertFalse(instruction instanceof LdcInsnNode ldc && ldc.cst instanceof String,method.name);
                    assertFalse(instruction instanceof InvokeDynamicInsnNode indy && indy.bsm.getOwner().endsWith("StringConcatFactory"));
                }
                if(node.name.equals("sample/Run"))assertEquals("retained-public-field",node.fields.getFirst().value);
                assertFalse(new String(jar.getInputStream(entry).readAllBytes(),java.nio.charset.StandardCharsets.ISO_8859_1).contains("native-only-marker-42f35a63"));
            }
        }
        assertTrue(Files.readString(temp.resolve("generated/native.cpp")).contains("env->NewString(ndkp_string_"));
        assertTrue(Files.readString(result.rules()).contains(" { *; }"));
    }
    @Test void packageBoundariesAndZeroSelectionNeedNoToolchain() throws Exception {
        Path classes=fixture();
        var result=new Transformer().transform(List.of(classes),temp.resolve("none"),"empty",Set.of(),false,Set.of("sam"),Set.of());
        assertEquals("0",Files.readString(temp.resolve("none/string-count.txt")));
        new NativeCompiler().compile(temp.resolve("none"),temp.resolve("native"),null,null,"empty",26,null,null);
        assertFalse(Files.exists(temp.resolve("native/jniLibs/arm64-v8a/libempty.so")));
        new Transformer().transform(List.of(classes),temp.resolve("excluded"),"empty",Set.of(),false,Set.of("sample"),Set.of("sample"));
        assertEquals("0",Files.readString(temp.resolve("excluded/string-count.txt")));
        assertThrows(IllegalArgumentException.class,()->StringProtection.packages(Set.of("sample.*")));
    }
    @Test void combinedSelectionDoesNotExtractMethodWrappers() throws Exception {
        var result=transform(fixture(),true);
        assertEquals(1,result.methods().size());
        String report=Files.readString(temp.resolve("generated/string-selection.json"));
        assertFalse(report.contains("sample/Run.converted"));
        String registration=Files.readString(result.registration());
        assertEquals(1,registration.split("JNI_OnLoad",-1).length-1);
        assertTrue(registration.contains("if(register_strings(env)!=0)return JNI_ERR;"));
    }
    @Test void unsupportedBootstrapAndDynamicConstantFailAtSource() throws Exception {
        for(boolean dynamic:List.of(false,true)) {
            ClassWriter writer=new ClassWriter(ClassWriter.COMPUTE_MAXS);
            writer.visit(Opcodes.V17,Opcodes.ACC_PUBLIC,"sample/Bad",null,"java/lang/Object",null);
            var method=writer.visitMethod(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC,"bad","()Ljava/lang/String;",null,null);
            method.visitCode();
            Handle bootstrap=new Handle(Opcodes.H_INVOKESTATIC,"sample/Bootstrap","custom","()V",false);
            if(dynamic)method.visitLdcInsn(new ConstantDynamic("text","Ljava/lang/String;",bootstrap));
            else method.visitInvokeDynamicInsn("text","()Ljava/lang/String;",bootstrap);
            method.visitInsn(Opcodes.ARETURN);method.visitMaxs(0,0);method.visitEnd();writer.visitEnd();
            Path classes=Files.createDirectories(temp.resolve("bad"+dynamic));Files.write(classes.resolve("Bad.class"),writer.toByteArray());
            var error=assertThrows(IllegalArgumentException.class,()->new Transformer().transform(List.of(classes),temp.resolve("bad-output"),"bad",Set.of(),false,Set.of("sample"),Set.of()));
            assertTrue(error.getMessage().contains("sample/Bad.bad"));
        }
    }
    @Test void stringsNativeMatchesJvm() throws Exception {
        String compiler=System.getProperty("dex2c.hostCompiler","");
        Assumptions.assumeFalse(compiler.isBlank(),"host JNI compiler required");
        Path input=fixture();
        Path jdk=Path.of(System.getProperty("java.home"));
        boolean windows=System.getProperty("os.name").startsWith("Windows");
        String java=jdk.resolve("bin/"+(windows?"java.exe":"java")).toString();
        String expected=run(List.of(java,"-Xcheck:jni","-cp",input+File.pathSeparator+System.getProperty("java.class.path"),"sample.Run"));
        for(boolean combined:List.of(false,true)) {
            var result=transform(input,combined);
            var compile=new ArrayList<>(List.of(compiler,"--driver-mode=g++","-std=gnu++17","-shared","-fno-exceptions","-I"+jdk.resolve("include"),
                "-I"+jdk.resolve("include/"+(windows?"win32":"linux")),result.nativeSource().toString(),
                temp.resolve("generated/native.cpp").toString(),result.registration().toString(),temp.resolve("generated/dex2c_runtime.cpp").toString(),
                "-o",temp.resolve(windows?"strings_test.dll":"libstrings_test.so").toString()));
            if(!windows)compile.add(1,"-fPIC");
            run(compile);
            for(String order:List.of("", "native-first")) {
                var command=new ArrayList<>(List.of(java,"-Xcheck:jni","-Djava.library.path="+temp,"-cp",result.classes()+File.pathSeparator+System.getProperty("java.class.path"),"sample.Run"));
                if(!order.isEmpty())command.add(order);
                assertEquals(expected,run(command));
            }
        }
    }
    @Test void stringsCompileToVerifiedArm64() throws Exception {
        String ndk=System.getProperty("dex2c.ndk",""),compiler=System.getProperty("dex2c.hostCompiler","");
        Assumptions.assumeFalse(ndk.isBlank()||compiler.isBlank(),"patched Clang and NDK required");
        transform(fixture(),false);
        new NativeCompiler().compile(temp.resolve("generated"),temp.resolve("native"),Path.of(ndk),Path.of(compiler),"strings_test",26,TestSigning.certificate(temp),TestSigning.python());
        String receipt=Files.readString(temp.resolve("native/protection.json"));
        assertTrue(receipt.contains("\"protectedMethods\":0"));
        assertFalse(receipt.contains("\"protectedStrings\":0"));
        assertTrue(receipt.contains("\"cseVmpMethods\":2"));
        String ir=Files.readString(temp.resolve("native/native.ll"));
        int count=Integer.parseInt(Files.readString(temp.resolve("generated/string-count.txt")));
        assertThrows(IllegalStateException.class,()->NativeCompiler.verifyStringIr(ir,count+1));
        assertThrows(IllegalStateException.class,()->NativeCompiler.verifyStringIr(ir.replaceFirst("call void @ndkp_decrypt_string_[0-9a-f]+", "call void @unprotected"),count));
    }
    private String run(List<String> command) throws Exception {
        Process process=new ProcessBuilder(command).redirectErrorStream(true).start();
        String output=new String(process.getInputStream().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(0,process.waitFor(),output);
        return output.replace("\r\n","\n");
    }
}
