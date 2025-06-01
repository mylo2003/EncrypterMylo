package com.encriptador.EncrypterMylo.model;

public class HybridEncryptedData {
    private byte[] encryptedFile;
    private byte[] encryptedKey;
    private byte[] privateKey;

    // Constructor
    public HybridEncryptedData(byte[] encryptedFile, byte[] encryptedKey, byte[] privateKey) {
        this.encryptedFile = encryptedFile;
        this.encryptedKey = encryptedKey;
        this.privateKey = privateKey;
    }

    // Getters
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


