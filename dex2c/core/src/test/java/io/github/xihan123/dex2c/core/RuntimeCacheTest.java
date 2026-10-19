package io.github.xihan123.dex2c.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class RuntimeCacheTest {
    @TempDir Path directory;
    @Test void fingerprintIgnoresSealerBytecodeCacheButTracksHeadersAndCertificate() throws Exception {
        Path runtime=Files.createDirectories(directory.resolve("runtime"));
        Path ndk=Files.createDirectories(directory.resolve("ndk"));
        Path resource=Files.createDirectories(directory.resolve("resource/include")).getParent();
        String host=System.getProperty("os.name").startsWith("Windows")?"windows-x86_64":"linux-x86_64";
        Path headers=Files.createDirectories(ndk.resolve("toolchains/llvm/prebuilt/"+host+"/sysroot/usr/include"));
        Path compiler=directory.resolve("compiler"),certificate=directory.resolve("cert");
        for(Path p:List.of(compiler,certificate,ndk.resolve("source.properties"),headers.resolve("header.h"),runtime.resolve("loader.cpp")))
            Files.writeString(p,"first");
        String original=NativeCompiler.runtimeFingerprint(runtime,compiler,ndk,resource,certificate);
        Path cache=Files.createDirectories(runtime.resolve("__pycache__"));Files.writeString(cache.resolve("seal_cse.pyc"),"generated");
        assertEquals(original,NativeCompiler.runtimeFingerprint(runtime,compiler,ndk,resource,certificate));
        Files.writeString(headers.resolve("header.h"),"changed");
        String changed=NativeCompiler.runtimeFingerprint(runtime,compiler,ndk,resource,certificate);
        assertNotEquals(original,changed);
        Files.writeString(certificate,"another signer");
        assertNotEquals(changed,NativeCompiler.runtimeFingerprint(runtime,compiler,ndk,resource,certificate));
    }
    @Test void cacheChecksContentAndInputsBeforeReusingAnArtifact() throws Exception {
        Path artifact=directory.resolve("input.txt"),log=directory.resolve("command.log"),cache=directory.resolve("cache");
        // Java --version succeeds without touching the stand-in artifact, so the test
        // can distinguish a real cache restore from execution without shell commands.
        Path java=Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"java.exe":"java");
        List<String> command=List.of(java.toString(),"--version");
        Files.writeString(artifact,"first"); NativeCompiler.cachedRun(command,log,artifact,cache,"inputs1");
        Files.writeString(artifact,"changed"); NativeCompiler.cachedRun(command,log,artifact,cache,"inputs1");
        assertEquals("first",Files.readString(artifact)); assertTrue(Files.readString(log).contains("cache hit"));
        Files.writeString(artifact,"second"); NativeCompiler.cachedRun(command,log,artifact,cache,"inputs2");
        assertEquals("second",Files.readString(artifact)); assertFalse(Files.readString(log).contains("cache hit"));
        try(var entries=Files.list(cache)) {
            for(Path entry:entries.toList())Files.writeString(entry.resolve("artifact"),"corrupt");
        }
        Files.writeString(artifact,"rebuilt"); NativeCompiler.cachedRun(command,log,artifact,cache,"inputs1");
        assertEquals("rebuilt",Files.readString(artifact)); assertFalse(Files.readString(log).contains("cache hit"));
    }
}
