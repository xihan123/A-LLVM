package io.github.xihan123.dex2c.gradle;

import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.SetProperty;

public abstract class Dex2cExtension {
    public abstract SetProperty<String> getBuildTypes();
    /** Optional locally rebuilt Clang; sysroot and libraries still come from android.ndkVersion/ndkPath. */
    public abstract RegularFileProperty getClangExecutable();
    /** Public DER/PEM certificate of the APK signer, never a private key or keystore. */
    public abstract RegularFileProperty getCertificateFile();
    /** Python 3 used by the bundled A-LLVM sealer; defaults to python on PATH. */
    public abstract RegularFileProperty getPythonExecutable();
}
