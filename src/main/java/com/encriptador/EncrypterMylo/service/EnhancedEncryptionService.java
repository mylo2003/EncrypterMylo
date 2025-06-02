package com.encriptador.EncrypterMylo.service;

import com.encriptador.EncrypterMylo.model.EncryptionAlgorithm;
import com.encriptador.EncrypterMylo.model.EncryptionMetadata;
import com.encriptador.EncrypterMylo.model.SignedHybridEncryptedData;
import org.springframework.stereotype.Service;
import javax.crypto.spec.ChaCha20ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

@Service
public class EnhancedEncryptionService {
    private final EnhancedKeyService keyService;
    private final CompressionService compressionService;
    private final DigitalSignatureService signatureService;
    private final CryptoUtilService cryptoUtilService;

    public EnhancedEncryptionService(EnhancedKeyService keyService, CompressionService compressionService,
                                     DigitalSignatureService signatureService, CryptoUtilService cryptoUtilService) {
        this.keyService = keyService;
        this.compressionService = compressionService;
        this.signatureService = signatureService;
        this.cryptoUtilService = cryptoUtilService;
    }

    public SignedHybridEncryptedData hybridEncryptEnhanced(byte[] fileBytes, String originalFileName,
                                                           EncryptionAlgorithm algorithm, boolean compress,
                                                           String contentType) throws Exception {
        if (fileBytes == null || fileBytes.length == 0) {
            throw new IllegalArgumentException("Archivo vacío o inválido.");
        }

        // Crear metadatos
        EncryptionMetadata metadata = new EncryptionMetadata(originalFileName, fileBytes.length,
                algorithm, compress, contentType);

        // 1. Comprimir si es necesario
        byte[] dataToEncrypt = fileBytes;
        if (compress) {
            dataToEncrypt = compressionService.compress(fileBytes);
            metadata.setCompressedSize(dataToEncrypt.length);
            System.out.println("[INFO] Archivo comprimido de " + fileBytes.length + " a " + dataToEncrypt.length + " bytes");
        } else {
            metadata.setCompressedSize(fileBytes.length);
        }

        // 2. Calcular checksum del archivo original
        String checksum = cryptoUtilService.calculateChecksum(fileBytes);
        metadata.setChecksum(checksum);

        // 3. Generar clave simétrica
        SecretKey symmetricKey = cryptoUtilService.generateSecretKey(algorithm);

        // 4. Cifrar archivo con algoritmo seleccionado
        byte[] encryptedFile = encryptWithAlgorithm(dataToEncrypt, symmetricKey, algorithm);

        // 5. Generar par de claves RSA
        KeyPair keyPair = keyService.generateRSAKeyPair();

        // 6. Cifrar la clave simétrica con RSA
        byte[] encryptedSymmetricKey = keyService.encryptSymmetricKeyWithRSA(symmetricKey, keyPair.getPublic());

        // 7. Firmar el archivo cifrado
        byte[] signature = signatureService.signData(encryptedFile, keyPair.getPrivate());

        System.out.println("[INFO] Archivo cifrado con " + algorithm.name() +
                ", firmado digitalmente y " + (compress ? "comprimido" : "sin comprimir"));

        return new SignedHybridEncryptedData(encryptedFile, encryptedSymmetricKey,
                keyPair.getPrivate().getEncoded(), signature, metadata);
    }

    private byte[] encryptWithAlgorithm(byte[] data, SecretKey key, EncryptionAlgorithm algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm.getTransformation());

        if (algorithm.getTransformation().contains("GCM")) {
            // Para AES-GCM, necesitamos un IV de 12 bytes (recomendado)
            byte[] iv = new byte[12];
            SecureRandom.getInstanceStrong().nextBytes(iv);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // 128-bit auth tag
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

            // Cifrar los datos
            byte[] encryptedData = cipher.doFinal(data);

            // Combinar IV + datos cifrados para almacenamiento/transmisión
            byte[] result = new byte[iv.length + encryptedData.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encryptedData, 0, result, iv.length, encryptedData.length);

            return result;

        } else if (algorithm.getTransformation().contains("ChaCha20")) {
            // ChaCha20 necesita un nonce de 12 bytes
            byte[] nonce = new byte[12];
            SecureRandom.getInstanceStrong().nextBytes(nonce);
            ChaCha20ParameterSpec chaChaSpec = new ChaCha20ParameterSpec(nonce, 0);
            cipher.init(Cipher.ENCRYPT_MODE, key, chaChaSpec);

            // Cifrar los datos
            byte[] encryptedData = cipher.doFinal(data);

            // Combinar nonce + datos cifrados
            byte[] result = new byte[nonce.length + encryptedData.length];
            System.arraycopy(nonce, 0, result, 0, nonce.length);
            System.arraycopy(encryptedData, 0, result, nonce.length, encryptedData.length);

            return result;

        } else if (algorithm.getTransformation().contains("ECB")) {
            // ECB no necesita IV (AES_128 y AES_256 de tu enum)
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);

        } else if (algorithm.getTransformation().contains("CBC")) {
            // Para CBC necesitamos un IV del tamaño del bloque (16 bytes para AES)
            byte[] iv = new byte[16];
            SecureRandom.getInstanceStrong().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

            // Cifrar los datos
            byte[] encryptedData = cipher.doFinal(data);

            // Combinar IV + datos cifrados
            byte[] result = new byte[iv.length + encryptedData.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encryptedData, 0, result, iv.length, encryptedData.length);

            return result;

        } else {
            // Para otros algoritmos, intenta sin parámetros adicionales
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        }
    }

    public byte[] hybridDecryptEnhanced(byte[] encryptedFile, byte[] encryptedSymmetricKey,
                                        PrivateKey privateKey, byte[] signature,
                                        EncryptionMetadata metadata) throws Exception {

        // 1. Verificar firma digital
        PublicKey publicKey = keyService.getPublicKeyFromPrivate(privateKey);
        boolean signatureValid = signatureService.verifySignature(encryptedFile, signature, publicKey);
        if (!signatureValid) {
            throw new SecurityException("La firma digital no es válida. El archivo puede haber sido modificado.");
        }
        System.out.println("[INFO] Firma digital verificada correctamente");

        // 2. Descifrar la clave simétrica
        SecretKey symmetricKey = keyService.decryptSymmetricKeyWithRSA(encryptedSymmetricKey, privateKey, metadata.getAlgorithm());

        // 3. Descifrar el archivo
        byte[] decryptedData = decryptWithAlgorithm(encryptedFile, symmetricKey, metadata.getAlgorithm());

        // 4. Descomprimir si fue comprimido
        if (metadata.isCompressed()) {
            decryptedData = compressionService.decompress(decryptedData);
            System.out.println("[INFO] Archivo descomprimido tras descifrado");
        }

        // 5. Validar checksum
        String checksum = cryptoUtilService.calculateChecksum(decryptedData);
        if (!checksum.equals(metadata.getChecksum())) {
            throw new SecurityException("El checksum no coincide. El archivo puede estar corrupto.");
        }
        System.out.println("[INFO] Checksum verificado correctamente");

        return decryptedData;
    }

    private byte[] decryptWithAlgorithm(byte[] encryptedData, SecretKey key, EncryptionAlgorithm algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm.getTransformation());

        if (algorithm.getTransformation().contains("GCM")) {
            // Extraer IV (primeros 12 bytes)
            byte[] iv = new byte[12];
            byte[] cipherText = new byte[encryptedData.length - 12];
            System.arraycopy(encryptedData, 0, iv, 0, 12);
            System.arraycopy(encryptedData, 12, cipherText, 0, cipherText.length);

            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

            return cipher.doFinal(cipherText);

        } else if (algorithm.getTransformation().contains("ChaCha20")) {
            // Extraer nonce (primeros 12 bytes)
            byte[] nonce = new byte[12];
            byte[] cipherText = new byte[encryptedData.length - 12];
            System.arraycopy(encryptedData, 0, nonce, 0, 12);
            System.arraycopy(encryptedData, 12, cipherText, 0, cipherText.length);

            ChaCha20ParameterSpec chaChaSpec = new ChaCha20ParameterSpec(nonce, 0);
            cipher.init(Cipher.DECRYPT_MODE, key, chaChaSpec);

            return cipher.doFinal(cipherText);

        } else if (algorithm.getTransformation().contains("ECB")) {
            // ECB no necesita IV
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(encryptedData);

        } else if (algorithm.getTransformation().contains("CBC")) {
            // Extraer IV (primeros 16 bytes)
            byte[] iv = new byte[16];
            byte[] cipherText = new byte[encryptedData.length - 16];
            System.arraycopy(encryptedData, 0, iv, 0, 16);
            System.arraycopy(encryptedData, 16, cipherText, 0, cipherText.length);

            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            return cipher.doFinal(cipherText);

        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(encryptedData);
        }
    }
}
