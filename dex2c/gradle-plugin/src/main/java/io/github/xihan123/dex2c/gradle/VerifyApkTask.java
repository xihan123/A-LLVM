package io.github.xihan123.dex2c.gradle;

import com.android.build.api.variant.BuiltArtifactsLoader;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.*;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Reads final signed APK outputs; never invokes a signing operation. */
@CacheableTask
public abstract class VerifyApkTask extends DefaultTask {
    @InputDirectory @org.gradle.api.tasks.Optional @PathSensitive(PathSensitivity.RELATIVE) public abstract DirectoryProperty getApkDirectory();
    @InputFiles @PathSensitive(PathSensitivity.NAME_ONLY) public abstract ConfigurableFileCollection getApkFiles();
    @InputDirectory @PathSensitive(PathSensitivity.RELATIVE) public abstract DirectoryProperty getNativeDirectory();
    @InputDirectory @PathSensitive(PathSensitivity.RELATIVE) public abstract DirectoryProperty getGeneratedDirectory();
    @InputFile @org.gradle.api.tasks.Optional @PathSensitive(PathSensitivity.NONE) public abstract RegularFileProperty getPythonExecutable();
    @InputFile @PathSensitive(PathSensitivity.NONE) public abstract RegularFileProperty getJavaExecutable();
    @InputFile @PathSensitive(PathSensitivity.NONE) public abstract RegularFileProperty getApkSigner();
    @Input public abstract Property<Integer> getMinSdk();
    @Internal public abstract Property<BuiltArtifactsLoader> getArtifactsLoader();
    @OutputFile public abstract RegularFileProperty getReport();
    @TaskAction public void verify() throws Exception {
        Path report = getReport().get().getAsFile().toPath();
        Files.deleteIfExists(report);
        if (Files.readString(getNativeDirectory().file("protection.json").get().getAsFile().toPath()).strip()
                .equals("{\"schemaVersion\":1,\"protectedMethods\":0}")) {
            Files.createDirectories(report.getParent());
            Files.writeString(report, "{\"schemaVersion\":1,\"protectedMethods\":0}\n");
            return;
        }
        if (!getPythonExecutable().isPresent()) throw new IllegalStateException("dex2c: Python 3 is required for final APK verification");
        List<String> apks = apkPaths();
        Path temp = getTemporaryDir().toPath();
        for (String file : List.of("verify_dex2c_apk.py", "dex2c_artifacts.py")) {
            try (var input = Objects.requireNonNull(getClass().getResourceAsStream("/a_llvm/" + file))) {
                Files.copy(input, temp.resolve(file), StandardCopyOption.REPLACE_EXISTING);
            }
        }
        List<String> command = new ArrayList<>(List.of(getPythonExecutable().get().getAsFile().toString(),
                temp.resolve("verify_dex2c_apk.py").toString(), "--native", getNativeDirectory().get().getAsFile().toString(),
                "--generated", getGeneratedDirectory().get().getAsFile().toString(), "--java", getJavaExecutable().get().getAsFile().toString(),
                "--apksigner", getApkSigner().get().getAsFile().toString(), "--min-sdk", getMinSdk().get().toString(),
                "--report", report.toString(), "--independent-apks"));
        for (String apk : apks) command.addAll(List.of("--apk", apk));
        Path log = temp.resolve("verify.log");
        Process process = new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile()).start();
        if (!process.waitFor(10, TimeUnit.MINUTES)) { process.destroyForcibly(); throw new IllegalStateException("dex2c: APK verification timed out"); }
        if (process.exitValue() != 0) throw new IllegalStateException("dex2c: final APK verification failed\n" + Files.readString(log));
        getLogger().lifecycle("dex2c: final APK verification; {}", getReport().get().getAsFile());
    }

    List<String> apkPaths() {
        if (!getApkFiles().isEmpty()) {
            if (getApkDirectory().isPresent()) throw new IllegalStateException("dex2c: select either APK files or an AGP APK directory");
            return getApkFiles().getFiles().stream().map(java.io.File::getAbsolutePath).sorted().toList();
        }
        if (!getApkDirectory().isPresent()) throw new IllegalStateException("dex2c: final APK outputs missing");
        var artifacts = getArtifactsLoader().get().load(getApkDirectory().get());
        if (artifacts == null || artifacts.getElements().isEmpty()) throw new IllegalStateException("dex2c: final APK outputs missing");
        return artifacts.getElements().stream().map(artifact -> artifact.getOutputFile()).toList();
    }
}
