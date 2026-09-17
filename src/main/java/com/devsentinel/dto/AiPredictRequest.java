package com.devsentinel.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request body POSTed to the Python AI service at /api/v1/predict.
 * Field names are camelCase and match the Pydantic aliases on the Python side.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AiPredictRequest {

    private String className;
    private String methodName;
    private String codeSnippet;
    private int startLine;

    /** Comma-separated hints from the static pass, e.g. "possible_sql_injection". */
    private String staticAnalysisHint;
}
