package com.encriptador.EncrypterMylo.controller;

import com.encriptador.EncrypterMylo.model.EncryptionAlgorithm;
import com.encriptador.EncrypterMylo.model.EncryptionMetadata;
import com.encriptador.EncrypterMylo.model.SignedHybridEncryptedData;
import com.encriptador.EncrypterMylo.service.EnhancedEncryptionService;
import com.encriptador.EncrypterMylo.utils.ZipUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.junrar.Archive;
import com.github.junrar.rarfile.FileHeader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/enhancedFile")
public class EnhancedFileController {
    @Autowired
    private EnhancedEncryptionService encryptionService;

    @PostMapping("/encrypt-enhanced")
    public ResponseEntity<ByteArrayResource> encryptEnhanced(
            @RequestParam("file") MultipartFile file,
            @RequestParam(defaultValue = "AES_256") EncryptionAlgorithm algorithm,
            @RequestParam(defaultValue = "false") boolean compress) throws Exception {

        SignedHybridEncryptedData result = encryptionService.hybridEncryptEnhanced(
                file.getBytes(),
                file.getOriginalFilename(),
                algorithm,
                compress,
                file.getContentType()
        );

        // Crear archivo ZIP con todos los componentes y metadatos
        Map<String, byte[]> files = new HashMap<>();
        files.put("encrypted_file", result.getEncryptedFile());
        files.put("encrypted_key.key", result.getEncryptedKey());
        files.put("private_key.key", result.getPrivateKey());
        files.put("signature.sig", result.getSignature());
        files.put("metadata.json", serializeMetadata(result.getMetadata()));

        byte[] zipBytes = ZipUtil.createZip(files);
        ByteArrayResource resource = new ByteArrayResource(zipBytes);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + file.getOriginalFilename() + "_encrypted.zip\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(zipBytes.length)
                .body(resource);
    }

    @PostMapping("/decrypt-enhanced")
    public ResponseEntity<byte[]> decryptEnhanced(
            @RequestParam("file") MultipartFile encryptedFile,
            @RequestParam("encryptedKey") MultipartFile encryptedKey,
            @RequestParam("privateKey") MultipartFile privateKeyFile,
            @RequestParam("signature") MultipartFile signatureFile,
            @RequestParam("metadata") MultipartFile metadataFile) throws Exception {

        // Reconstruir la clave privada
        PrivateKey privateKey = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(privateKeyFile.getBytes()));

        // Deserializar metadatos
        EncryptionMetadata metadata = deserializeMetadata(metadataFile.getBytes());

        // Descifrar archivo
        byte[] original = encryptionService.hybridDecryptEnhanced(
                encryptedFile.getBytes(),
                encryptedKey.getBytes(),
                privateKey,
                signatureFile.getBytes(),
                metadata
        );

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + metadata.getOriginalFileName() + "\"")
                .contentType(metadata.getContentType() != null ?
                        MediaType.parseMediaType(metadata.getContentType()) :
                        MediaType.APPLICATION_OCTET_STREAM)
                .body(original);
    }

    @PostMapping("/decrypt-from-archive")
    public ResponseEntity<byte[]> decryptFromArchive(
            @RequestParam("archive") MultipartFile archiveFile) throws Exception {

        try {
            // Extraer archivos del ZIP/RAR
            Map<String, byte[]> extractedFiles = extractArchive(archiveFile);

            // Validar que existan todos los componentes necesarios
            validateExtractedFiles(extractedFiles);

            // Obtener los componentes necesarios
            byte[] encryptedFileData = extractedFiles.get("encrypted_file");
            byte[] encryptedKeyData = extractedFiles.get("encrypted_key.key");
            byte[] privateKeyData = extractedFiles.get("private_key.key");
            byte[] signatureData = extractedFiles.get("signature.sig");
            byte[] metadataData = extractedFiles.get("metadata.json");

            // Reconstruir la clave privada
            PrivateKey privateKey = KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(privateKeyData));

            // Deserializar metadatos
            EncryptionMetadata metadata = deserializeMetadata(metadataData);

            // Descifrar archivo
            byte[] original = encryptionService.hybridDecryptEnhanced(
                    encryptedFileData,
                    encryptedKeyData,
                    privateKey,
                    signatureData,
                    metadata
            );

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment; filename=\"" + metadata.getOriginalFileName() + "\"")
                    .contentType(metadata.getContentType() != null ?
                            MediaType.parseMediaType(metadata.getContentType()) :
                            MediaType.APPLICATION_OCTET_STREAM)
                    .body(original);

        } catch (Exception e) {
            throw new RuntimeException("Error al procesar archivo comprimido: " + e.getMessage(), e);
        }
    }

    private Map<String, byte[]> extractArchive(MultipartFile archiveFile) throws Exception {
        Map<String, byte[]> extractedFiles = new HashMap<>();
        String fileName = archiveFile.getOriginalFilename().toLowerCase();

        if (fileName.endsWith(".zip")) {
            extractedFiles = extractZipFile(archiveFile);
        } else if (fileName.endsWith(".rar")) {
            extractedFiles = extractRarFile(archiveFile);
        } else {
            throw new IllegalArgumentException("Formato de archivo no soportado. Solo ZIP y RAR están permitidos.");
        }

        return extractedFiles;
    }

    private Map<String, byte[]> extractZipFile(MultipartFile zipFile) throws Exception {
        Map<String, byte[]> extractedFiles = new HashMap<>();

        try (ZipInputStream zipIn = new ZipInputStream(zipFile.getInputStream())) {
            ZipEntry entry;

            while ((entry = zipIn.getNextEntry()) != null) {
                if (!entry.isDirectory()) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    int len;

                    while ((len = zipIn.read(buffer)) > 0) {
                        baos.write(buffer, 0, len);
                    }

                    extractedFiles.put(entry.getName(), baos.toByteArray());
                }
                zipIn.closeEntry();
            }
        }

        return extractedFiles;
    }

    private Map<String, byte[]> extractRarFile(MultipartFile rarFile) throws Exception {
        Map<String, byte[]> extractedFiles = new HashMap<>();

        // Crear archivo temporal
        File tempFile = File.createTempFile("temp_rar", ".rar");
        try {
            rarFile.transferTo(tempFile);

            // Usar junrar para extraer RAR
            Archive archive = new Archive(tempFile);
            FileHeader fileHeader;

            while ((fileHeader = archive.nextFileHeader()) != null) {
                if (!fileHeader.isDirectory()) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    archive.extractFile(fileHeader, baos);
                    extractedFiles.put(fileHeader.getFileName(), baos.toByteArray());
                }
            }

            archive.close();
        } finally {
            // Limpiar archivo temporal
            if (tempFile.exists()) {
                tempFile.delete();
            }
        }

        return extractedFiles;
    }

    private void validateExtractedFiles(Map<String, byte[]> extractedFiles) {
        String[] requiredFiles = {
                "encrypted_file",
                "encrypted_key.key",
                "private_key.key",
                "signature.sig",
                "metadata.json"
        };

        List<String> missingFiles = new ArrayList<>();

        for (String requiredFile : requiredFiles) {
            if (!extractedFiles.containsKey(requiredFile) || extractedFiles.get(requiredFile) == null) {
                missingFiles.add(requiredFile);
            }
        }

        if (!missingFiles.isEmpty()) {
            throw new IllegalArgumentException(
                    "Archivos faltantes en el comprimido: " + String.join(", ", missingFiles)
            );
        }
    }

    @GetMapping("/algorithms")
    public ResponseEntity<EncryptionAlgorithm[]> getSupportedAlgorithms() {
        return ResponseEntity.ok(EncryptionAlgorithm.values());
    }

    private byte[] serializeMetadata(EncryptionMetadata metadata) throws Exception {
        // Implementación simple con JSON
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        return mapper.writeValueAsBytes(metadata);
    }

    private EncryptionMetadata deserializeMetadata(byte[] data) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        return mapper.readValue(data, EncryptionMetadata.class);
    }
}
