package com.devsentinel.controller;

import com.devsentinel.client.AiAnalysisClient;
import com.devsentinel.dto.AiServiceStatus;
import com.devsentinel.model.AnalysisRecord;
import com.devsentinel.service.AnalysisService;
import com.devsentinel.service.UploadValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JSON API mirroring the web UI. Useful for curl/Postman demonstrations and
 * for showing that the analysis engine is independent of the presentation layer.
 */
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class ApiController {

    private final AnalysisService analysisService;
    private final UploadValidator uploadValidator;
    private final AiAnalysisClient aiAnalysisClient;

    @PostMapping(value = "/analyze",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AnalysisRecord> analyze(@RequestParam("file") MultipartFile file)
            throws IOException {

        uploadValidator.validate(file);
        byte[] bytes = file.getBytes();
        uploadValidator.validateContent(bytes, file.getOriginalFilename());

        AnalysisRecord record = analysisService.analyse(file.getOriginalFilename(), bytes);
        return ResponseEntity.status(HttpStatus.CREATED).body(record);
    }

    @GetMapping(value = "/analyses/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AnalysisRecord> getAnalysis(@PathVariable Long id) {
        return analysisService.findById(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Reports the health of both halves of the system. Hit this before a demo:
     *   curl http://localhost:8080/api/v1/status
     */
    @GetMapping(value = "/status", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> status() {
        AiServiceStatus ai = aiAnalysisClient.checkStatus();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("application", "UP");
        body.put("staticAnalysis", "AVAILABLE");
        body.put("aiService", ai.getLabel());
        body.put("aiModelLoaded", ai.isModelLoaded());
        body.put("aiModelName", ai.getModelName());
        body.put("mode", ai.isReachable() ? "FULL" : "DEGRADED");
        body.put("detail", ai.getDetail());
        return ResponseEntity.ok(body);
    }
}
