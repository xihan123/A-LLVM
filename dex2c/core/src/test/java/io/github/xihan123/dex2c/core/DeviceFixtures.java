package io.github.xihan123.dex2c.core;

import javax.tools.ToolProvider;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;

/** Builds durable inputs for tests/dex2c/device.py without involving a host app. */
public final class DeviceFixtures {
    public static void main(String[] args) throws Exception {
        Path out=Path.of(args[0]).toAbsolutePath();Files.createDirectories(out);
        Path source=out.resolve("Run.java"),classes=Files.createDirectories(out.resolve("classes"));
        try(InputStream in=DeviceFixtures.class.getResourceAsStream("/fixtures/Run.java")){Files.copy(Objects.requireNonNull(in),source,StandardCopyOption.REPLACE_EXISTING);}
        int result=ToolProvider.getSystemJavaCompiler().run(null,null,null,"-g","-classpath",System.getProperty("java.class.path"),"-d",classes.toString(),source.toString());
        if(result!=0)throw new IllegalStateException("fixture compilation failed");
        Path kotlin=location(kfixture.Fixture.class);
        Path generated=out.resolve("generated");new Transformer().transform(List.of(classes,kotlin),generated,"dex2c_semantics");
        new NativeCompiler().compile(generated,out.resolve("native"),Path.of(args[1]),Path.of(args[2]),"dex2c_semantics",26,
                TestSigning.certificate(out),TestSigning.python());
        Path javaJar=out.resolve("original.jar");
        try(JarOutputStream jar=new JarOutputStream(Files.newOutputStream(javaJar));var files=Files.walk(classes)) {
            for(Path path:files.filter(Files::isRegularFile).toList()) {
                JarEntry entry=new JarEntry(classes.relativize(path).toString().replace('\\','/'));entry.setTime(0);jar.putNextEntry(entry);Files.copy(path,jar);jar.closeEntry();
            }
        }
        var common=List.of(location(io.github.xihan123.dex2c.runtime.Dex2cRuntime.class),location(kotlin.Unit.class));
        Files.writeString(out.resolve("inputs.json"),"{\"baseline\":["+Transformer.json(javaJar.toString())+","+Transformer.json(kotlin.toString())
                +"],\"protected\":["+Transformer.json(generated.resolve("classes.jar").toString())+"],\"common\":["
                +String.join(",",common.stream().map(p->Transformer.json(p.toString())).toList())+"]}\n");
        System.out.println("dex2c device fixtures: "+out);
    }
    private static Path location(Class<?> type) throws Exception {return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI());}
}
