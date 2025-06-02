package com.encriptador.EncrypterMylo.service;

import com.encriptador.EncrypterMylo.model.EncryptionAlgorithm;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;

@Service
public class EnhancedKeyService extends KeyService {

    public SecretKey decryptSymmetricKeyWithRSA(byte[] encryptedKey, PrivateKey privateKey,
                                                EncryptionAlgorithm algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decrypted, algorithm.getAlgorithm());
    }

    public byte[] encryptSymmetricKeyWithRSA(SecretKey symmetricKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey.getEncoded());
    }

    public PublicKey getPublicKeyFromPrivate(PrivateKey privateKey) throws Exception {
        // En un caso real, deberías guardar la clave pública por separado
        // Esto es una implementación simplificada
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) privateKey;
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                rsaPrivateKey.getModulus(),
                rsaPrivateKey.getPublicExponent()
        );
        return keyFactory.generatePublic(publicKeySpec);
    }
}
