package io.github.xihan123.dex2c.gradle;

import io.github.xihan123.dex2c.core.NativeCompiler;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.*;
import org.gradle.api.provider.*;
import org.gradle.api.tasks.*;
import java.nio.file.Path;

@CacheableTask
public abstract class NativeTask extends DefaultTask {
    @InputDirectory @PathSensitive(PathSensitivity.RELATIVE) public abstract DirectoryProperty getGeneratedDirectory();
    @Internal public abstract DirectoryProperty getNdkDirectory();
    /** Read selection at input snapshot time, after the transform; never freeze it in configuration cache. */
    @InputFiles @PathSensitive(PathSensitivity.RELATIVE) public java.util.List<java.io.File> getNdkInputs() {
        return ProtectionCoordinator.hasProtection(getGeneratedDirectory().get()) && getNdkDirectory().isPresent()
                ?java.util.List.of(getNdkDirectory().get().getAsFile()):java.util.List.of();
    }
    @InputFile @Optional @PathSensitive(PathSensitivity.NONE) public abstract RegularFileProperty getClangExecutable();
    @InputFile @Optional @PathSensitive(PathSensitivity.NONE) public abstract RegularFileProperty getCertificateFile();
    @InputFile @Optional @PathSensitive(PathSensitivity.NONE) public abstract RegularFileProperty getPythonExecutable();
    @Input public abstract Property<Integer> getMinSdk();
    @Input public abstract Property<String> getLibraryName();
    @Input public abstract Property<Boolean> getSegmentedData();
    @Input public abstract Property<Boolean> getVerifyApkSignature();
    @OutputDirectory public abstract DirectoryProperty getOutputDirectory();
    @Internal public abstract DirectoryProperty getJniDirectory();
    @Internal public abstract DirectoryProperty getAssetsDirectory();
    @TaskAction public void compile() throws Exception {
        Path compiler=getClangExecutable().isPresent()?getClangExecutable().get().getAsFile().toPath():null;
        new NativeCompiler().compile(getGeneratedDirectory().get().getAsFile().toPath(),getOutputDirectory().get().getAsFile().toPath(),
                getNdkDirectory().isPresent()?getNdkDirectory().get().getAsFile().toPath():null,compiler,getLibraryName().get(),getMinSdk().get(),
                getCertificateFile().isPresent()?getCertificateFile().get().getAsFile().toPath():null,
                getPythonExecutable().isPresent()?getPythonExecutable().get().getAsFile().toPath():null,getSegmentedData().get(),getVerifyApkSignature().get());
        getLogger().lifecycle("dex2c: verified native library; {}",getOutputDirectory().file("protection.json").get().getAsFile());
    }
}
