package com.devsentinel.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Turns exceptions into friendly output.
 *
 * Browser requests get a redirect back to the form with a flash message;
 * /api/** requests get structured JSON. Stack traces are logged server-side and
 * never shown to the user.
 */
@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public Object handleTooLarge(MaxUploadSizeExceededException ex,
                                 HttpServletRequest request,
                                 RedirectAttributes redirectAttributes) {
        String message = "That file is too large. The upload limit is 1 MB.";
        log.info("Rejected oversized upload");
        return respond(request, redirectAttributes, HttpStatus.PAYLOAD_TOO_LARGE,
                "FILE_TOO_LARGE", message);
    }

    @ExceptionHandler(AnalysisException.class)
    public Object handleAnalysisError(AnalysisException ex,
                                      HttpServletRequest request,
                                      RedirectAttributes redirectAttributes) {
        log.info("Analysis error: {}", ex.getMessage());
        return respond(request, redirectAttributes, HttpStatus.BAD_REQUEST,
                "ANALYSIS_ERROR", ex.getMessage());
    }

    /**
     * Catch-all. A database outage or any unexpected bug lands here: the user
     * sees a generic apology, the details go to the log.
     */
    /**
     * Missing static resources (favicon, a stale CSS path) must keep their
     * natural 404 rather than being redirected to the home page.
     */
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<Void> handleMissingResource(NoResourceFoundException ex) {
        return ResponseEntity.notFound().build();
    }

    @ExceptionHandler(Exception.class)
    public Object handleUnexpected(Exception ex,
                                   HttpServletRequest request,
                                   RedirectAttributes redirectAttributes) {
        log.error("Unexpected error handling {}", request.getRequestURI(), ex);
        String message = "Something went wrong while processing that request. "
                + "Please try again, or check the application logs if the problem persists.";
        return respond(request, redirectAttributes, HttpStatus.INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR", message);
    }

    /** JSON for API callers, redirect-with-flash-message for browser users. */
    private Object respond(HttpServletRequest request,
                           RedirectAttributes redirectAttributes,
                           HttpStatus status,
                           String code,
                           String message) {

        if (request.getRequestURI().startsWith("/api/")) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("timestamp", LocalDateTime.now());
            body.put("status", status.value());
            body.put("errorCode", code);
            body.put("message", message);
            return ResponseEntity.status(status).body(body);
        }

        redirectAttributes.addFlashAttribute("errorMessage", message);
        return "redirect:/";
    }
}
