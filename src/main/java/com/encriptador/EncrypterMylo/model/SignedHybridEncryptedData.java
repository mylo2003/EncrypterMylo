package com.encriptador.EncrypterMylo.model;

public class SignedHybridEncryptedData {
    private final byte[] encryptedFile;
    private final byte[] encryptedKey;
    private final byte[] privateKey;
    private final byte[] signature;
    private final EncryptionMetadata metadata;

    public SignedHybridEncryptedData(byte[] encryptedFile, byte[] encryptedKey,
                                     byte[] privateKey, byte[] signature, EncryptionMetadata metadata) {
        this.encryptedFile = encryptedFile;
        this.encryptedKey = encryptedKey;
        this.privateKey = privateKey;
        this.signature = signature;
        this.metadata = metadata;
    }

    // Getters
    public byte[] getEncryptedFile() { return encryptedFile; }
    public byte[] getEncryptedKey() { return encryptedKey; }
    public byte[] getPrivateKey() { return privateKey; }
    public byte[] getSignature() { return signature; }
    public EncryptionMetadata getMetadata() { return metadata; }
}
