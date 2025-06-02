package com.encriptador.EncrypterMylo.model;

import java.time.LocalDateTime;

public class EncryptionMetadata {
    private String originalFileName;
    private long originalSize;
    private long compressedSize;
    private EncryptionAlgorithm algorithm;
    private LocalDateTime encryptionTime;
    private String checksum;
    private boolean compressed;
    private String contentType;

    public EncryptionMetadata() {
    }

    // Constructor
    public EncryptionMetadata(String originalFileName, long originalSize,
                              EncryptionAlgorithm algorithm, boolean compressed, String contentType) {
        this.originalFileName = originalFileName;
        this.originalSize = originalSize;
        this.algorithm = algorithm;
        this.compressed = compressed;
        this.contentType = contentType;
        this.encryptionTime = LocalDateTime.now();
    }

    // Getters y Setters
    public String getOriginalFileName() { return originalFileName; }
    public void setOriginalFileName(String originalFileName) { this.originalFileName = originalFileName; }

    public long getOriginalSize() { return originalSize; }
    public void setOriginalSize(long originalSize) { this.originalSize = originalSize; }

    public long getCompressedSize() { return compressedSize; }
    public void setCompressedSize(long compressedSize) { this.compressedSize = compressedSize; }

    public EncryptionAlgorithm getAlgorithm() { return algorithm; }
    public void setAlgorithm(EncryptionAlgorithm algorithm) { this.algorithm = algorithm; }

    public LocalDateTime getEncryptionTime() { return encryptionTime; }
    public void setEncryptionTime(LocalDateTime encryptionTime) { this.encryptionTime = encryptionTime; }

    public String getChecksum() { return checksum; }
    public void setChecksum(String checksum) { this.checksum = checksum; }

    public boolean isCompressed() { return compressed; }
    public void setCompressed(boolean compressed) { this.compressed = compressed; }

    public String getContentType() { return contentType; }
    public void setContentType(String contentType) { this.contentType = contentType; }
}
