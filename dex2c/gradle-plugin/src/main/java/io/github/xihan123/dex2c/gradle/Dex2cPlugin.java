package io.github.xihan123.dex2c.gradle;

import org.gradle.api.*;

public final class Dex2cPlugin implements Plugin<Project> {
    @Override public void apply(Project project) {
        Dex2cExtension extension=project.getExtensions().create("dex2c",Dex2cExtension.class);
        extension.getBuildTypes().convention(java.util.Set.of("release"));
        extension.getInheritedMethods().convention(java.util.Set.of());
        extension.getSegmentedData().convention(false);
        extension.getVerifyApkSignature().convention(false);
        project.getPluginManager().withPlugin("com.android.application",ignored->{
            project.getDependencies().add("compileOnly","io.github.xihan123.dex2c:annotations:0.1.15-dev");
            project.getDependencies().add("implementation","io.github.xihan123.dex2c:runtime:0.1.15-dev");
        });
        ProtectionCoordinator.install(project);
    }
}
