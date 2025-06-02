package com.encriptador.EncrypterMylo.model;

public enum EncryptionAlgorithm {
    AES_128("AES", 128, "AES/ECB/PKCS5Padding"),
    AES_256("AES", 256, "AES/ECB/PKCS5Padding"),
    AES_GCM_128("AES", 128, "AES/GCM/NoPadding"),
    AES_GCM_256("AES", 256, "AES/GCM/NoPadding"),
    CHACHA20("ChaCha20", 256, "ChaCha20");

    private final String algorithm;
    private final int keySize;
    private final String transformation;

    EncryptionAlgorithm(String algorithm, int keySize, String transformation) {
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.transformation = transformation;
    }

    public String getAlgorithm() { return algorithm; }
    public int getKeySize() { return keySize; }
    public String getTransformation() { return transformation; }
}
