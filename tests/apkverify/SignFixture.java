import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.io.*;

// Disposable test keys only. Signs test signed-data, never release artifacts.
public class SignFixture {
    public static void main(String[] a) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(Path.of(a[0]))) { store.load(in, "android".toCharArray()); }
        var key = (PrivateKey) store.getKey("test", "android".toCharArray());
        Signature signature = Signature.getInstance(a[3]);
        if (a[3].equals("RSASSA-PSS")) {
            String hash = a[4]; int length = hash.equals("SHA-256") ? 32 : 64;
            signature.setParameter(new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(hash), length, 1));
        }
        signature.initSign(key); signature.update(Files.readAllBytes(Path.of(a[1])));
        Files.write(Path.of(a[2]), signature.sign());
        Files.write(Path.of(a[2] + ".pub"), store.getCertificate("test").getPublicKey().getEncoded());
        Files.write(Path.of(a[2] + ".der"), store.getCertificate("test").getEncoded());
    }
}
