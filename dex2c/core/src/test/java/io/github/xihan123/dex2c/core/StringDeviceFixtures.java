package io.github.xihan123.dex2c.core;

import javax.tools.ToolProvider;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;

/** Durable Java/Kotlin inputs for the existing ART/certificate differential runner. */
public final class StringDeviceFixtures {
    public static void main(String[] args) throws Exception {
        Path out=Path.of(args[0]).toAbsolutePath();Files.createDirectories(out);
        Path source=out.resolve("Run.java"),classes=Files.createDirectories(out.resolve("classes"));
        try(var input=StringDeviceFixtures.class.getResourceAsStream("/fixtures/strings/Run.java")) {
            Files.copy(Objects.requireNonNull(input),source,StandardCopyOption.REPLACE_EXISTING);
        }
        Path benchmark=out.resolve("Benchmark.java");Files.writeString(benchmark,benchmark());
        if(ToolProvider.getSystemJavaCompiler().run(null,null,null,"-g","-cp",System.getProperty("java.class.path"),"-d",classes.toString(),source.toString(),benchmark.toString())!=0)
            throw new IllegalStateException("string fixture compilation failed");
        Path kotlin=location(kfixture.Fixture.class),generated=out.resolve("generated");
        boolean combined=args.length>3&&Boolean.parseBoolean(args[3]);
        new Transformer().transform(List.of(classes,kotlin),generated,"dex2c_semantics",Set.of(),combined,Set.of("sample","kfixture"),Set.of());
        new NativeCompiler().compile(generated,out.resolve("native"),Path.of(args[1]),Path.of(args[2]),"dex2c_semantics",26,
            TestSigning.certificate(out),TestSigning.python(),false,args.length>4&&Boolean.parseBoolean(args[4]));
        Path original=out.resolve("original.jar");
        try(var jar=new JarOutputStream(Files.newOutputStream(original));var files=Files.walk(classes)) {
            for(Path path:files.filter(Files::isRegularFile).toList()) {
                jar.putNextEntry(new JarEntry(classes.relativize(path).toString().replace('\\','/')));Files.copy(path,jar);jar.closeEntry();
            }
        }
        Files.writeString(out.resolve("inputs.json"),"{\"mains\":[\"sample.Run\",\"kfixture.FixtureKt\"],\"baseline\":["+Transformer.json(original.toString())+","+Transformer.json(kotlin.toString())
            +"],\"protected\":["+Transformer.json(generated.resolve("classes.jar").toString())+"],\"common\":["+Transformer.json(location(kotlin.Unit.class).toString())+"]}\n");
        System.out.println("String device fixtures: "+out);
    }
    private static String benchmark() {
        StringBuilder cases=new StringBuilder();
        for(int i=0;i<256;i++)cases.append("case ").append(i).append(": return \"benchmark-unique-").append(i).append("-6d8830e12429\";\n");
        return """
            package sample;
            import java.nio.file.*;
            public final class Benchmark {
                static volatile String sink;
                static String literal(int index) { switch(index) {
            """+cases+"""
                    default: throw new AssertionError();
                }}
                static long heap() { Runtime r=Runtime.getRuntime(); return r.totalMemory()-r.freeMemory(); }
                public static void main(String[] args) throws Exception {
                    System.gc();
                    long before=heap(), start=System.nanoTime();
                    sink=literal(0);
                    long first=System.nanoTime()-start;
                    for(int i=1;i<256;i++)sink=literal(i);
                    long cold=System.nanoTime()-start, retained=heap()-before;
                    for(int i=0;i<20000;i++)sink=literal(i&255);
                    start=System.nanoTime();
                    for(int i=0;i<2000000;i++)sink=literal(i&255);
                    long hot=System.nanoTime()-start;
                    long pss=Files.readAllLines(Paths.get("/proc/self/smaps_rollup")).stream()
                        .filter(s->s.startsWith("Pss:")).mapToLong(s->Long.parseLong(s.trim().split(" +")[1])*1024).findFirst().orElse(-1);
                    System.out.println("{\\"firstNanos\\":"+first+",\\"cold256Nanos\\":"+cold+",\\"hotNanosPerRead\\":"+(hot/2000000.0)
                        +",\\"javaHeapDeltaBytes\\":"+retained+",\\"pssBytes\\":"+pss+"}");
                }
            }
            """;
    }
    private static Path location(Class<?> type) throws Exception {return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI());}
}
