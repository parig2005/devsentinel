package com.devsentinel.exception;

/** The uploaded file failed validation (wrong type, empty, too large, bad name). */
public class InvalidUploadException extends AnalysisException {
    public InvalidUploadException(String message) {
        super(message);
    }
}
