package org.example.config.keys;


import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.stereotype.Component;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;


@Component
public class KeyManager {

    public RSAKey generateRsaKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair =  keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        return new RSAKey.Builder((RSAPublicKey) publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
    }
}
