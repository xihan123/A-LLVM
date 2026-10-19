package io.github.xihan123.dex2c.core;

import java.io.File;
import java.nio.file.*;
import java.util.*;

/** Disposable test identity, also used to sign the ART fixture APK. */
final class TestSigning {
    static Path certificate(Path output) throws Exception {
        Files.createDirectories(output);
        Path store=output.resolve("test.jks"),cert=output.resolve("test.der");
        String keytool=Path.of(System.getProperty("java.home"),"bin","keytool").toString();
        if(!Files.exists(store))run(List.of(keytool,"-genkeypair","-keystore",store.toString(),"-storepass","android",
                "-keypass","android","-alias","test","-keyalg","RSA","-dname","CN=dex2c test","-validity","3650","-noprompt"));
        Files.deleteIfExists(cert);
        run(List.of(keytool,"-exportcert","-keystore",store.toString(),"-storepass","android","-alias","test","-file",cert.toString()));
        return cert;
    }
    static Path python() {
        String name=System.getProperty("os.name").startsWith("Windows")?"python.exe":"python3";
        return Arrays.stream(System.getenv("PATH").split(java.util.regex.Pattern.quote(File.pathSeparator)))
                .map(dir->Path.of(dir,name)).filter(Files::isRegularFile).findFirst().orElseThrow();
    }
    private static void run(List<String> command) throws Exception {
        Process process=new ProcessBuilder(command).redirectErrorStream(true).start();
        String output=new String(process.getInputStream().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8);
        if(process.waitFor()!=0)throw new IllegalStateException(output);
    }
}
