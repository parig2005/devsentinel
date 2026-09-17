package com.devsentinel.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * A single method extracted from the AST, ready to be scored by the AI service.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CodeSnippet {

    private String className;
    private String methodName;
    private String sourceCode;
    private int startLine;
    private int endLine;

    /** Hints produced by the static rule pass; may be null. */
    private String staticAnalysisHint;
}
