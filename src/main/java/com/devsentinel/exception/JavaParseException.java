package com.devsentinel.exception;

/** The uploaded file is not syntactically valid Java and could not be parsed. */
public class JavaParseException extends AnalysisException {
    public JavaParseException(String message) {
        super(message);
    }

    public JavaParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
