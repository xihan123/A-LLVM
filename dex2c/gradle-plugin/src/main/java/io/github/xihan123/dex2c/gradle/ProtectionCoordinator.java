package io.github.xihan123.dex2c.gradle;

import com.android.build.api.variant.*;
import com.android.build.api.artifact.ScopedArtifact;
import com.android.build.api.artifact.SingleArtifact;
import io.github.xihan123.dex2c.core.MethodKey;
import org.gradle.api.*;
import org.gradle.api.file.*;
import org.gradle.api.provider.Provider;
import java.nio.file.Files;

/** Both plugin entrypoints share one transform and native build per variant. */
final class ProtectionCoordinator {
    static void install(Project project) {
        String key="aLlvmProtectionCoordinator";
        if(project.getExtensions().getExtraProperties().has(key))return;
        project.getExtensions().getExtraProperties().set(key,true);
        project.getPluginManager().withPlugin("com.android.application",ignored->configure(project));
    }

    static Provider<RegularFile> python(Project project) {
        return project.getLayout().file(project.getProviders().environmentVariable("PATH").map(path->
            java.util.Arrays.stream(path.split(java.util.regex.Pattern.quote(java.io.File.pathSeparator)))
                .map(dir->new java.io.File(dir,System.getProperty("os.name").startsWith("Windows")?"python.exe":"python3"))
                .filter(java.io.File::isFile).findFirst().orElse(null)));
    }

    static RegularFileProperty merge(Project project,String name,RegularFileProperty first,RegularFileProperty second) {
        var result=project.getObjects().fileProperty();
        if(first!=null && first.isPresent())result.set(first);
        if(second!=null && second.isPresent()) {
            if(result.isPresent() && !result.get().getAsFile().toPath().toAbsolutePath().normalize()
                    .equals(second.get().getAsFile().toPath().toAbsolutePath().normalize()))
                throw new GradleException("A-LLVM: conflicting "+name+" between dex2c and stringProtection");
            result.set(second);
        }
        return result;
    }

    static boolean hasProtection(Directory directory) {
        try {
            var path=directory.getAsFile().toPath();
            for(String name:java.util.List.of("symbols.txt","native-symbols.txt","string-symbols.txt"))
                if(Files.exists(path.resolve(name)) && !Files.readString(path.resolve(name)).isBlank())return true;
            return false;
        } catch(java.io.IOException error) {throw new GradleException("Cannot read protection selection",error);}
    }
    @SuppressWarnings({"rawtypes","unchecked"})
    private static void configure(Project project) {
        AndroidComponentsExtension components=project.getExtensions().getByType(AndroidComponentsExtension.class);
        var buildTools=project.getObjects().property(String.class);
        var configuredNdk=project.getObjects().directoryProperty();
        components.finalizeDsl((Action<com.android.build.api.dsl.ApplicationExtension>)dsl->{
            dsl.getAndroidResources().getNoCompress().add("qseg");buildTools.set(dsl.getBuildToolsVersion());
            if(dsl.getNdkPath()!=null)configuredNdk.set(project.file(dsl.getNdkPath()));
            else if(dsl.getNdkVersion()!=null) {
                String version=dsl.getNdkVersion();
                configuredNdk.set(components.getSdkComponents().getSdkDirectory().map(sdk->sdk.dir("ndk/"+version)));
            }
        });
        if(components.getPluginVersion().getMajor()!=9)throw new GradleException("dex2c 0.1 requires AGP 9 (validated with 9.4.1)");
        components.onVariants(components.selector().all(),(Action<Variant>)variant->{
            Dex2cExtension dex=project.getExtensions().findByType(Dex2cExtension.class);
            StringProtectionExtension strings=project.getExtensions().findByType(StringProtectionExtension.class);
            boolean methods=dex!=null && dex.getBuildTypes().get().contains(variant.getBuildType());
            boolean literals=strings!=null && strings.getBuildTypes().get().contains(variant.getBuildType());
            if(!methods && !literals)return;
            if(literals && (!strings.getIncludePackages().isPresent() || strings.getIncludePackages().get().isEmpty()))
                throw new GradleException("strings: includePackages must explicitly select at least one package");
            var certificate=merge(project,"certificateFile",methods?dex.getCertificateFile():null,literals?strings.getCertificateFile():null);
            var clang=merge(project,"clangExecutable",methods?dex.getClangExecutable():null,literals?strings.getClangExecutable():null);
            var python=merge(project,"pythonExecutable",methods?dex.getPythonExecutable():null,literals?strings.getPythonExecutable():null);
            boolean verifySignature=(methods && dex.getVerifyApkSignature().get()) || (literals && strings.getVerifyApkSignature().get());
            if(variant.getMinSdk().getApiLevel()<26)throw new GradleException("dex2c requires minSdk >= 26");
            String name=variant.getName();
            var library=variant.getNamespace().map(namespace->new MethodKey(namespace,name,"()V").bridge());
            var transform=project.getTasks().register(variant.computeTaskName("transform","Dex2c"),TransformTask.class,task->{
                task.getLibraryName().set(library);
                task.getInheritedMethods().set(methods?dex.getInheritedMethods().get():java.util.Set.of());
                task.getConvertMethods().set(methods);
                task.getStringIncludes().set(literals?strings.getIncludePackages().get():java.util.Set.of());
                task.getStringExcludes().set(literals?strings.getExcludePackages().get():java.util.Set.of());
                task.getGeneratedDirectory().set(project.getLayout().getBuildDirectory().dir("intermediates/dex2c/"+name+"/generated"));
                task.getOutputJar().set(task.getGeneratedDirectory().file("classes.jar"));
                task.getKeepRules().set(task.getGeneratedDirectory().file("keep-rules.pro"));
            });
            variant.getArtifacts().forScope(ScopedArtifacts.Scope.ALL).use(transform).toTransform(ScopedArtifact.CLASSES.INSTANCE,
                    TransformTask::getInputJars,TransformTask::getInputDirectories,TransformTask::getOutputJar);
            variant.getProguardFiles().add(transform.flatMap(TransformTask::getKeepRules));
            var nativeTask=project.getTasks().register(variant.computeTaskName("compile","Dex2cNative"),NativeTask.class,task->{
                task.getGeneratedDirectory().set(transform.flatMap(TransformTask::getGeneratedDirectory));
                task.getNdkDirectory().set(configuredNdk);
                task.getClangExecutable().set(clang);
                task.getCertificateFile().set(certificate);
                task.getPythonExecutable().set(python);
                task.getLibraryName().set(library);task.getMinSdk().set(variant.getMinSdk().getApiLevel());
                task.getSegmentedData().set(methods && dex.getSegmentedData().get());
                task.getVerifyApkSignature().set(verifySignature);
                task.getOutputDirectory().set(project.getLayout().getBuildDirectory().dir("intermediates/dex2c/"+name+"/native"));
                task.getJniDirectory().set(task.getOutputDirectory().dir("jniLibs"));
                task.getAssetsDirectory().set(task.getOutputDirectory().dir("assets"));
            });
            if(variant.getSources().getJniLibs()==null)throw new GradleException("dex2c: variant has no jniLibs source provider");
            variant.getSources().getJniLibs().addGeneratedSourceDirectory(nativeTask,NativeTask::getJniDirectory);
            if(variant.getSources().getAssets()==null)throw new GradleException("dex2c: variant has no assets source provider");
            variant.getSources().getAssets().addGeneratedSourceDirectory(nativeTask,NativeTask::getAssetsDirectory);
            var verify=project.getTasks().register(variant.computeTaskName("verify","Dex2cApk"),VerifyApkTask.class,task->{
                task.getApkDirectory().set(variant.getArtifacts().get(SingleArtifact.APK.INSTANCE));
                task.getArtifactsLoader().set(variant.getArtifacts().getBuiltArtifactsLoader());
                task.getNativeDirectory().set(nativeTask.flatMap(NativeTask::getOutputDirectory));
                task.getGeneratedDirectory().set(transform.flatMap(TransformTask::getGeneratedDirectory));
                task.getPythonExecutable().set(python);
                task.getJavaExecutable().set(new java.io.File(System.getProperty("java.home"),"bin/java"+(System.getProperty("os.name").startsWith("Windows")?".exe":"")));
                task.getApkSigner().set(components.getSdkComponents().getSdkDirectory().zip(buildTools,
                        (sdk,version)->sdk.file("build-tools/"+version+"/lib/apksigner.jar")));
                task.getMinSdk().set(variant.getMinSdk().getApiLevel());
                task.getReport().set(project.getLayout().getBuildDirectory().file("reports/dex2c/"+name+"/apk-verification.json"));
            });
            String assembleName="assemble"+Character.toUpperCase(name.charAt(0))+name.substring(1);
            project.getTasks().matching(t->t.getName().equals(assembleName))
                    .configureEach(t->t.dependsOn(verify));
        });
    }
}
