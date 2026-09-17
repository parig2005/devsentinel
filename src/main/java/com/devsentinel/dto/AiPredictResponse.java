package com.devsentinel.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response body returned by the Python AI service.
 *
 * `vulnerabilityType` is the literal string "NONE" when the service found
 * nothing, which the analyzer treats as a clean snippet.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class AiPredictResponse {

    private String vulnerabilityType;
    private double severityScore;
    private String issueDescription;
    private String suggestedFix;
    private String owaspCategory;

    /** 0.0–1.0 CodeBERT semantic similarity, or 0.5 in rule-only mode. */
    private double confidence;

    /** Model id, or "rule-only" when the transformer could not be loaded. */
    private String modelVersion;

    /** True when this response is the client's offline fallback, not a real reply. */
    @Builder.Default
    private boolean fallback = false;

    public boolean hasFinding() {
        return vulnerabilityType != null
                && !vulnerabilityType.isBlank()
                && !"NONE".equalsIgnoreCase(vulnerabilityType);
    }

    /** Neutral response used when the AI service is unreachable. */
    public static AiPredictResponse offlineFallback() {
        return AiPredictResponse.builder()
                .vulnerabilityType("NONE")
                .severityScore(0.0)
                .issueDescription("AI service unavailable for this snippet.")
                .confidence(0.0)
                .modelVersion("unavailable")
                .fallback(true)
                .build();
    }
}
