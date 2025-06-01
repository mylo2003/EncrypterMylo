package com.encriptador.EncrypterMylo.controller;

import com.encriptador.EncrypterMylo.model.HybridEncryptedData;
import com.encriptador.EncrypterMylo.service.EncryptionService;
import com.encriptador.EncrypterMylo.utils.ZipUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;


import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/file")
public class FileController {
    @Autowired
    private EncryptionService encryptionService;

    @PostMapping("/encrypt-hybrid")
    public ResponseEntity<ByteArrayResource> encryptHybrid(@RequestParam("file") MultipartFile file) throws Exception {
        HybridEncryptedData result = encryptionService.hybridEncrypt(file.getBytes());

        byte[] encryptedFile = result.getEncryptedFile();
        byte[] encryptedKey = result.getEncryptedKey();
        byte[] privateKey = result.getPrivateKey();

        Map<String, byte[]> files = new HashMap<>();
        files.put("encrypted_file", encryptedFile);
        files.put("encrypted_key.key", encryptedKey);
        files.put("private_key.key", privateKey);

        byte[] zipBytes = ZipUtil.createZip(files);
        ByteArrayResource resource = new ByteArrayResource(zipBytes);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"encryption_result.zip\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(zipBytes.length)
                .body(resource);
    }

    @PostMapping("/decrypt-hybrid")
    public ResponseEntity<byte[]> decryptHybrid(
            @RequestParam("file") MultipartFile encryptedFile,
            @RequestParam("encryptedKey") MultipartFile encryptedKey,
            @RequestParam("privateKey") MultipartFile privateKeyFile
    ) throws Exception {
        PrivateKey privateKey = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(privateKeyFile.getBytes()));

        byte[] original = encryptionService.hybridDecrypt(
                encryptedFile.getBytes(),
                encryptedKey.getBytes(),
                privateKey
        );

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"decrypted_file\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(original);
    }
}
