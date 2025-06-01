package com.encriptador.EncrypterMylo.service;

import com.encriptador.EncrypterMylo.model.HybridEncryptedData;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;

@Service
public class EncryptionService {
    private final KeyService keyService;

    public EncryptionService(KeyService keyService) {
        this.keyService = keyService;
    }

    public HybridEncryptedData hybridEncrypt(byte[] fileBytes) throws Exception {
        if (fileBytes == null || fileBytes.length == 0) {
            throw new IllegalArgumentException("Archivo vacío o inválido.");
        }
        System.out.println("[INFO] Archivo cifrado con AES y clave AES cifrada con RSA.");

        // 1. Generar clave AES
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();

        // 2. Cifrar archivo con AES
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedFile = aesCipher.doFinal(fileBytes);

        // 3. Generar par de claves RSA
        KeyPair keyPair = keyService.generateRSAKeyPair();

        // 4. Encriptar la clave AES con la clave pública RSA
        byte[] encryptedAesKey = keyService.encryptAESKeyWithRSA(aesKey, keyPair.getPublic());

        return new HybridEncryptedData(encryptedFile, encryptedAesKey, keyPair.getPrivate().getEncoded());
    }

    public byte[] hybridDecrypt(byte[] encryptedFile, byte[] encryptedAesKey, PrivateKey privateKey) throws Exception {
        SecretKey aesKey = keyService.decryptAESKeyWithRSA(encryptedAesKey, privateKey);

        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

        return aesCipher.doFinal(encryptedFile);
    }
}
