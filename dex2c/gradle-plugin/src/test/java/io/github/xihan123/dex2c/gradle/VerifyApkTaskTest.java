package io.github.xihan123.dex2c.gradle;

import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.nio.file.Files;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class VerifyApkTaskTest {
    @TempDir Path directory;

    private VerifyApkTask task() {
        var project = ProjectBuilder.builder().withProjectDir(directory.toFile()).build();
        return project.getTasks().create("verifyDistribution", VerifyApkTask.class);
    }

    @Test void explicitDistributionFilesDoNotRequireAgpMetadata() {
        var task = task();
        var apk = directory.resolve("module-arm64.apk").toFile();
        task.getApkFiles().from(apk);
        assertEquals(List.of(apk.getAbsolutePath()), task.apkPaths());
    }

    @Test void ambiguousSourcesAreRejected() {
        var task = task();
        task.getApkFiles().from(directory.resolve("module.apk"));
        task.getApkDirectory().set(directory.toFile());
        assertThrows(IllegalStateException.class, task::apkPaths);
    }

    @Test void missingOutputsAreRejected() {
        assertThrows(IllegalStateException.class, task()::apkPaths);
    }

    @Test void zeroReceiptRequiresEmptySelection() throws Exception {
        var task = task();
        var report = directory.resolve("report.json");
        task.getNativeDirectory().set(directory.toFile());
        task.getGeneratedDirectory().set(directory.toFile());
        task.getReport().set(report.toFile());
        Path apk = directory.resolve("plain.apk");
        Files.writeString(apk, "plain APK fixture");
        task.getApkFiles().from(apk);
        Files.writeString(directory.resolve("protection.json"), "{\"schemaVersion\":1,\"protectedMethods\":0}");
        task.verify();
        assertTrue(Files.exists(report));
        String result = Files.readString(report);
        assertTrue(result.contains("\"validationStatus\":\"not-applicable\""));
        assertTrue(result.contains("\"file\":\"plain.apk\""));
        assertTrue(result.contains("\"sha256\":"));
        Path requirements = directory.resolve("requirements.json");
        Files.writeString(requirements, "{}");
        task.getRequirementsFile().set(requirements.toFile());
        assertThrows(IllegalStateException.class, task::verify);
        assertFalse(Files.exists(report));
        task.getRequirementsFile().unset();
        Files.writeString(directory.resolve("string-symbols.txt"), "d2c_string_dispatcher\n");
        var error = assertThrows(IllegalStateException.class, task::verify);
        assertTrue(error.getMessage().contains("zero protection receipt differs"));
        assertFalse(Files.exists(report));
    }

    @Test void verifierShipsItsTransitivePythonDependencies() throws Exception {
        var scripts = directory.resolve("scripts");
        task().prepareVerifierScripts(scripts);
        for (String file : List.of("verify_dex2c_apk.py", "dex2c_artifacts.py", "seal_qseg.py", "seal_cse.py"))
            assertTrue(Files.size(scripts.resolve(file)) > 0, file);
    }
}
