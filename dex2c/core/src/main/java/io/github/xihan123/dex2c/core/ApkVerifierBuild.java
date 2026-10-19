package io.github.xihan123.dex2c.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.AlgorithmParameters;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.*;
import java.util.concurrent.*;

/** Bundle the pinned verifier with the plugin; no consumer network dependency. */
final class ApkVerifierBuild {
    static void prepare(Path runtime, byte[] certificate) throws Exception {
        validateKey(CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certificate)).getPublicKey());
        try (var input = Objects.requireNonNull(ApkVerifierBuild.class.getResourceAsStream("/a_llvm/apkverify-resources.txt"));
             var reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            for (String line : reader.lines().toList()) {
                String[] parts = line.split(" ", 2);
                if (parts.length != 2 || !parts[0].matches("[a-f0-9]{64}")) throw new IOException("invalid verifier resource index");
                Path output = runtime.resolve(parts[1]).normalize();
                if (!output.startsWith(runtime) || parts[1].contains("\\")) throw new IOException("invalid verifier resource path");
                byte[] bytes;
                try (var source = Objects.requireNonNull(ApkVerifierBuild.class.getResourceAsStream("/a_llvm/" + parts[1]))) { bytes = source.readAllBytes(); }
                if (!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals(parts[0]))
                    throw new IOException("verifier resource digest mismatch: " + parts[1]);
                Files.createDirectories(output.getParent()); Files.write(output, bytes);
            }
        }
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate);
        List<String> values = new ArrayList<>(); for (byte b : digest) values.add(Integer.toString(b & 255));
        Files.writeString(runtime.resolve("apkverify_policy.h"), "#include <cstdint>\nstatic const uint8_t ndkp_expected_certificate[32]={"
                + String.join(",", values) + "};\n");
    }

    // Reject a certificate that apksigner could accept but the trimmed native profile cannot parse.
    static void validateKey(PublicKey key) throws Exception {
        if (key instanceof RSAPublicKey rsa && key.getAlgorithm().equals("RSA") && rsa.getModulus().bitLength() <= 8192) return;
        if (key instanceof ECPublicKey ec) {
            var actual = ec.getParams();
            for (String curve : List.of("secp256r1", "secp384r1", "secp521r1")) {
                var parameters = AlgorithmParameters.getInstance("EC"); parameters.init(new ECGenParameterSpec(curve));
                var supported = parameters.getParameterSpec(ECParameterSpec.class);
                if (actual.getCurve().equals(supported.getCurve()) && actual.getGenerator().equals(supported.getGenerator())
                        && actual.getOrder().equals(supported.getOrder()) && actual.getCofactor() == supported.getCofactor()) return;
            }
        }
        throw new IllegalArgumentException("dex2c: unsupported APK verification public key; use RSA (up to 8192 bits) or EC P-256/P-384/P-521");
    }

    static List<String> compile(List<String> common, Path runtime, Path output, Path cache, String key) throws Exception {
        List<String> flags = new ArrayList<>(common);
        flags.addAll(List.of("-Oz", "-fno-lto", "-I" + runtime, "-I" + runtime.resolve("third_party/mbedtls/include"),
                "-include", runtime.resolve("apkverify_build.h").toString()));
        List<Path> sources = new ArrayList<>();
        for (String name : Files.readAllLines(runtime.resolve("apkverify_sources.txt"))) {
            if (!name.matches("[a-z0-9_]+")) throw new IOException("invalid crypto source name");
            sources.add(runtime.resolve("third_party/mbedtls/library/" + name + ".c"));
        }
        sources.add(runtime.resolve("apkverify.cpp")); sources.add(runtime.resolve("ndkp_apkverify.cpp"));
        List<String> objects = new ArrayList<>(); List<Future<?>> jobs = new ArrayList<>();
        try (var executor = Executors.newFixedThreadPool(Math.min(8, Runtime.getRuntime().availableProcessors()))) {
            for (Path source : sources) {
                String name = source.getFileName().toString();
                Path object = output.resolve("apkverify-" + name + ".o"); objects.add(object.toString());
                List<String> command = new ArrayList<>(flags);
                if (name.endsWith(".c")) {
                    command.removeAll(List.of("--driver-mode=g++", "-std=gnu++17", "-fno-exceptions", "-frtti"));
                    command.addAll(List.of("-x", "c", "-std=c11"));
                }
                command.addAll(List.of("-c", source.toString(), "-o", object.toString()));
                jobs.add(executor.submit(() -> {
                    NativeCompiler.cachedRun(command, output.resolve("apkverify-" + name + ".log"), object, cache, key); return null;
                }));
            }
            for (var job : jobs) job.get();
        }
        return objects;
    }
}
