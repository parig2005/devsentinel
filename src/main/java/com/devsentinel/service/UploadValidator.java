package com.devsentinel.service;

import com.devsentinel.exception.InvalidUploadException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;

/**
 * Validates uploads before anything touches the parser.
 *
 * Security note: DevSentinel only ever READS the uploaded text. It never
 * compiles or executes it, so a malicious .java file cannot run here. These
 * checks exist to reject junk input and bound resource use.
 */
@Component
public class UploadValidator {

    private final long maxBytes;

    public UploadValidator(@Value("${spring.servlet.multipart.max-file-size:1MB}") String maxFileSize) {
        this.maxBytes = DataSize.parse(maxFileSize).toBytes();
    }

    public void validate(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new InvalidUploadException(
                    "No file was selected, or the file is empty. Please choose a .java file.");
        }

        String name = file.getOriginalFilename();
        if (name == null || name.isBlank()) {
            throw new InvalidUploadException("The uploaded file has no name.");
        }

        // Reject path traversal in the supplied name before it is ever logged
        // or echoed back into a template.
        if (name.contains("..") || name.contains("/") || name.contains("\\")) {
            throw new InvalidUploadException("The file name contains invalid path characters.");
        }

        if (!name.toLowerCase().endsWith(".java")) {
            throw new InvalidUploadException(
                    "Only .java source files are supported. You uploaded: " + sanitise(name));
        }

        if (file.getSize() > maxBytes) {
            throw new InvalidUploadException(
                    "File is too large. The limit is " + (maxBytes / 1024) + " KB.");
        }
    }

    /**
     * Rejects binary content masquerading as source, and files with no Java
     * structure at all. Cheap sanity check before invoking the parser.
     */
    public void validateContent(byte[] bytes, String fileName) {
        if (bytes.length == 0) {
            throw new InvalidUploadException("'" + sanitise(fileName) + "' is empty.");
        }

        // A NUL byte in the first KB means this is not a text file.
        int scanLimit = Math.min(bytes.length, 1024);
        for (int i = 0; i < scanLimit; i++) {
            if (bytes[i] == 0) {
                throw new InvalidUploadException(
                        "'" + sanitise(fileName) + "' appears to be a binary file, not Java source.");
            }
        }

        String text = new String(bytes, StandardCharsets.UTF_8);
        if (!text.contains("class") && !text.contains("interface")
                && !text.contains("enum") && !text.contains("record")) {
            throw new InvalidUploadException(
                    "'" + sanitise(fileName) + "' does not contain a Java type declaration.");
        }
    }

    /** Strips anything that could confuse a log line or an error message. */
    public static String sanitise(String value) {
        if (value == null) return "";
        String cleaned = value.replaceAll("[\\r\\n\\t<>]", "");
        return cleaned.length() > 120 ? cleaned.substring(0, 120) + "..." : cleaned;
    }
}
