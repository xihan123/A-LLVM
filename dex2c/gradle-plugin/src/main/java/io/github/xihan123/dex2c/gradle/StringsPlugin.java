package io.github.xihan123.dex2c.gradle;

import org.gradle.api.*;

public final class StringsPlugin implements Plugin<Project> {
    @Override public void apply(Project project) {
        var extension=project.getExtensions().create("stringProtection",StringProtectionExtension.class);
        extension.getBuildTypes().convention(java.util.Set.of("release"));
        extension.getExcludePackages().convention(java.util.Set.of());
        extension.getVerifyApkSignature().convention(false);
        extension.getPythonExecutable().convention(ProtectionCoordinator.python(project));
        ProtectionCoordinator.install(project);
    }
}
