package io.github.xihan123.dex2c.gradle;

import com.android.build.api.variant.*;
import com.android.build.api.artifact.ScopedArtifact;
import io.github.xihan123.dex2c.core.MethodKey;
import org.gradle.api.*;

public final class Dex2cPlugin implements Plugin<Project> {
    @Override public void apply(Project project) {
        Dex2cExtension extension=project.getExtensions().create("dex2c",Dex2cExtension.class);
        extension.getBuildTypes().convention(java.util.Set.of("release"));
        extension.getPythonExecutable().convention(project.getLayout().file(project.getProviders().environmentVariable("PATH").map(path->
                java.util.Arrays.stream(path.split(java.util.regex.Pattern.quote(java.io.File.pathSeparator)))
                        .map(dir->new java.io.File(dir,System.getProperty("os.name").startsWith("Windows")?"python.exe":"python3"))
                        .filter(java.io.File::isFile).findFirst().orElse(null))));
        project.getPluginManager().withPlugin("com.android.application",ignored->configure(project,extension));
    }
    @SuppressWarnings({"rawtypes","unchecked"})
    private static void configure(Project project,Dex2cExtension extension) {
        project.getDependencies().add("compileOnly","io.github.xihan123.dex2c:annotations:0.1.3");
        project.getDependencies().add("implementation","io.github.xihan123.dex2c:runtime:0.1.3");
        AndroidComponentsExtension components=project.getExtensions().getByType(AndroidComponentsExtension.class);
        if(components.getPluginVersion().getMajor()!=9)throw new GradleException("dex2c 0.1 requires AGP 9 (validated with 9.4.1)");
        components.onVariants(components.selector().all(),(Action<Variant>)variant->{
            if(!extension.getBuildTypes().get().contains(variant.getBuildType()))return;
            if(variant.getMinSdk().getApiLevel()<26)throw new GradleException("dex2c requires minSdk >= 26");
            String name=variant.getName();
            var library=variant.getNamespace().map(namespace->new MethodKey(namespace,name,"()V").bridge());
            var transform=project.getTasks().register(variant.computeTaskName("transform","Dex2c"),TransformTask.class,task->{
                task.getLibraryName().set(library);
                task.getGeneratedDirectory().set(project.getLayout().getBuildDirectory().dir("intermediates/dex2c/"+name+"/generated"));
                task.getOutputJar().set(task.getGeneratedDirectory().file("classes.jar"));
                task.getKeepRules().set(task.getGeneratedDirectory().file("keep-rules.pro"));
            });
            variant.getArtifacts().forScope(ScopedArtifacts.Scope.ALL).use(transform).toTransform(ScopedArtifact.CLASSES.INSTANCE,
                    TransformTask::getInputJars,TransformTask::getInputDirectories,TransformTask::getOutputJar);
            variant.getProguardFiles().add(transform.flatMap(TransformTask::getKeepRules));
            var nativeTask=project.getTasks().register(variant.computeTaskName("compile","Dex2cNative"),NativeTask.class,task->{
                task.getGeneratedDirectory().set(transform.flatMap(TransformTask::getGeneratedDirectory));
                task.getNdkDirectory().set(components.getSdkComponents().getNdkDirectory());
                task.getClangExecutable().set(extension.getClangExecutable());
                task.getCertificateFile().set(extension.getCertificateFile());
                task.getPythonExecutable().set(extension.getPythonExecutable());
                task.getLibraryName().set(library);task.getMinSdk().set(variant.getMinSdk().getApiLevel());
                task.getOutputDirectory().set(project.getLayout().getBuildDirectory().dir("intermediates/dex2c/"+name+"/native"));
                task.getJniDirectory().set(task.getOutputDirectory().dir("jniLibs"));
            });
            if(variant.getSources().getJniLibs()==null)throw new GradleException("dex2c: variant has no jniLibs source provider");
            variant.getSources().getJniLibs().addGeneratedSourceDirectory(nativeTask,NativeTask::getJniDirectory);
        });
    }
}
