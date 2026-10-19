package io.github.xihan123.dex2c.gradle;

import io.github.xihan123.dex2c.core.Transformer;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.*;
import org.gradle.api.provider.*;
import org.gradle.api.tasks.*;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;

@CacheableTask
public abstract class TransformTask extends DefaultTask {
    @Classpath public abstract ListProperty<RegularFile> getInputJars();
    @Classpath public abstract ListProperty<Directory> getInputDirectories();
    @Input public abstract Property<String> getLibraryName();
    @OutputDirectory public abstract DirectoryProperty getGeneratedDirectory();
    @OutputFile public abstract RegularFileProperty getOutputJar();
    @Internal public abstract RegularFileProperty getKeepRules();
    @TaskAction public void transform() throws IOException {
        List<Path> inputs=new ArrayList<>();
        for(RegularFile file:getInputJars().get())inputs.add(file.getAsFile().toPath());
        for(Directory directory:getInputDirectories().get())inputs.add(directory.getAsFile().toPath());
        var result=new Transformer().transform(inputs,getGeneratedDirectory().get().getAsFile().toPath(),getLibraryName().get());
        // ScopedArtifacts assigns the final output path when wiring the transform.
        Path artifact=getOutputJar().get().getAsFile().toPath();
        if(!result.classes().toAbsolutePath().equals(artifact.toAbsolutePath())) {
            Files.createDirectories(artifact.getParent());
            Files.copy(result.classes(),artifact,StandardCopyOption.REPLACE_EXISTING);
        }
        getLogger().lifecycle("dex2c: selected {} methods; {}",result.methods().size(),result.report());
    }
}
