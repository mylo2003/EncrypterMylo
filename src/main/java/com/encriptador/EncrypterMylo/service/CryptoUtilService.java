package com.encriptador.EncrypterMylo.service;

import com.encriptador.EncrypterMylo.model.EncryptionAlgorithm;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.MessageDigest;
import java.util.Base64;

@Service
public class CryptoUtilService {

    public String calculateChecksum(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);
        return Base64.getEncoder().encodeToString(hash);
    }

    public SecretKey generateSecretKey(EncryptionAlgorithm algorithm) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm.getAlgorithm());
        keyGen.init(algorithm.getKeySize());
        return keyGen.generateKey();
    }
}
