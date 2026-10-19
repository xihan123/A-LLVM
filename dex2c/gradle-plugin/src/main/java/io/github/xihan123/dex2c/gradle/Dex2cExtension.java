package io.github.xihan123.dex2c.gradle;

import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.SetProperty;
import org.gradle.api.provider.Property;

public abstract class Dex2cExtension {
    /** Opt-in native APK v2/v3 verification before protected code executes. */
    public abstract Property<Boolean> getVerifyApkSignature();
    /** Opt-in authenticated asset segments. Requires A-LLVM LLVM 21 with segmented-data support. */
    public abstract Property<Boolean> getSegmentedData();
    public abstract SetProperty<String> getBuildTypes();
    /** Explicit class#method(JVM descriptor) roots; callbacks use native CSE instead of VMP. */
    public abstract SetProperty<String> getInheritedMethods();
    /** Optional locally rebuilt Clang; sysroot and libraries still come from android.ndkVersion/ndkPath. */
    public abstract RegularFileProperty getClangExecutable();
    /** Public DER/PEM certificate of the APK signer, never a private key or keystore. */
    public abstract RegularFileProperty getCertificateFile();
    /** Python 3 used by the bundled A-LLVM sealer; defaults to python on PATH. */
    public abstract RegularFileProperty getPythonExecutable();
}
