package io.github.xihan123.dex2c.gradle;

import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.*;

public abstract class StringProtectionExtension {
    public abstract SetProperty<String> getBuildTypes();
    /** Required opt-in packages, including subpackages. */
    public abstract SetProperty<String> getIncludePackages();
    public abstract SetProperty<String> getExcludePackages();
    public abstract RegularFileProperty getCertificateFile();
    public abstract RegularFileProperty getClangExecutable();
    public abstract RegularFileProperty getPythonExecutable();
    public abstract Property<Boolean> getVerifyApkSignature();
}
