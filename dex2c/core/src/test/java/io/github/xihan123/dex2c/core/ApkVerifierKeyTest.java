package io.github.xihan123.dex2c.core;

import org.junit.jupiter.api.Test;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import static org.junit.jupiter.api.Assertions.*;

class ApkVerifierKeyTest {
    @Test void supportedPublicKeys() throws Exception {
        var rsa = KeyPairGenerator.getInstance("RSA"); rsa.initialize(2048);
        ApkVerifierBuild.validateKey(rsa.generateKeyPair().getPublic());
        for (String curve : new String[]{"secp256r1", "secp384r1", "secp521r1"}) {
            var ec = KeyPairGenerator.getInstance("EC"); ec.initialize(new ECGenParameterSpec(curve));
            ApkVerifierBuild.validateKey(ec.generateKeyPair().getPublic());
        }
    }
    @Test void excludedPublicKeyIsRejectedBeforeNativeCompilation() {
        PublicKey key = new PublicKey() {
            public String getAlgorithm() { return "DSA"; }
            public String getFormat() { return "X.509"; }
            public byte[] getEncoded() { return new byte[0]; }
        };
        assertThrows(IllegalArgumentException.class, () -> ApkVerifierBuild.validateKey(key));
    }
}
