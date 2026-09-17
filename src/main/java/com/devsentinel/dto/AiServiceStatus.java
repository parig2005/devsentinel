package com.devsentinel.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Snapshot of the Python AI service health, shown in the UI header so you can
 * demonstrate degraded mode without opening a terminal.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AiServiceStatus {

    private boolean reachable;

    /** True when the transformer weights are actually loaded on the Python side. */
    private boolean modelLoaded;

    private String modelName;
    private String detail;

    public String getLabel() {
        if (!reachable) return "DEGRADED";
        return modelLoaded ? "ONLINE" : "ONLINE (rule-only)";
    }

    public String getCssClass() {
        if (!reachable) return "status-degraded";
        return modelLoaded ? "status-online" : "status-partial";
    }

    public static AiServiceStatus offline(String detail) {
        return AiServiceStatus.builder()
                .reachable(false)
                .modelLoaded(false)
                .modelName("n/a")
                .detail(detail)
                .build();
    }
}
