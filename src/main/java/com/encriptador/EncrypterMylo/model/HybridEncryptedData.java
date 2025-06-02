package com.encriptador.EncrypterMylo.model;

public class HybridEncryptedData {
    private final byte[] encryptedFile;
    private final byte[] encryptedKey;
    private final byte[] privateKey;

    public HybridEncryptedData(byte[] encryptedFile, byte[] encryptedKey, byte[] privateKey) {
        this.encryptedFile = encryptedFile;
        this.encryptedKey = encryptedKey;
        this.privateKey = privateKey;
    }

    public byte[] getEncryptedFile() {
        return encryptedFile;
    }

    public byte[] getEncryptedKey() {
        return encryptedKey;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }
}


