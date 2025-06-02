package com.encriptador.EncrypterMylo.controller;

import com.encriptador.EncrypterMylo.model.EncryptionAlgorithm;
import com.encriptador.EncrypterMylo.model.EncryptionMetadata;
import com.encriptador.EncrypterMylo.model.SignedHybridEncryptedData;
import com.encriptador.EncrypterMylo.service.EnhancedEncryptionService;
import com.encriptador.EncrypterMylo.utils.ZipUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

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
