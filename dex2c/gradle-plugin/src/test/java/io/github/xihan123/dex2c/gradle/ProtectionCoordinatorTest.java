package io.github.xihan123.dex2c.gradle;

import org.gradle.api.GradleException;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;

class ProtectionCoordinatorTest {
    @TempDir Path temp;

    @Test void bothEntrypointsInstallExactlyOneCoordinatorInEitherOrder() {
        for(boolean reverse:new boolean[]{false,true}) {
            var project=ProjectBuilder.builder().withProjectDir(temp.resolve("project"+reverse).toFile()).build();
            project.getPluginManager().apply(reverse?StringsPlugin.class:Dex2cPlugin.class);
            project.getPluginManager().apply(reverse?Dex2cPlugin.class:StringsPlugin.class);
            assertNotNull(project.getExtensions().getByType(Dex2cExtension.class));
            assertNotNull(project.getExtensions().getByType(StringProtectionExtension.class));
            assertEquals(true,project.getExtensions().getExtraProperties().get("aLlvmProtectionCoordinator"));
        }
    }
    @Test void sharedInputsMergeAndConflictsFailBeforeNativeCompilation() {
        var project=ProjectBuilder.builder().withProjectDir(temp.toFile()).build();
        var first=project.getObjects().fileProperty();
        var second=project.getObjects().fileProperty();
        assertFalse(ProtectionCoordinator.merge(project,"clangExecutable",first,second).isPresent());
        first.set(temp.resolve("clang").toFile());
        assertEquals(first.get(),ProtectionCoordinator.merge(project,"clangExecutable",first,second).get());
        second.set(temp.resolve("clang").toFile());
        assertDoesNotThrow(()->ProtectionCoordinator.merge(project,"clangExecutable",first,second));
        second.set(temp.resolve("other-clang").toFile());
        assertThrows(GradleException.class,()->ProtectionCoordinator.merge(project,"clangExecutable",first,second));
    }
    @Test void nativeToolchainIsNeededOnlyForNonemptySelections() throws Exception {
        var project=ProjectBuilder.builder().withProjectDir(temp.toFile()).build();
        var directory=project.getLayout().getProjectDirectory();
        for(String name:new String[]{"symbols.txt","native-symbols.txt","string-symbols.txt"})Files.writeString(temp.resolve(name),"");
        assertFalse(ProtectionCoordinator.hasProtection(directory));
        Files.writeString(temp.resolve("string-symbols.txt"),"d2c_string_dispatcher\n");
        assertTrue(ProtectionCoordinator.hasProtection(directory));
    }
}
