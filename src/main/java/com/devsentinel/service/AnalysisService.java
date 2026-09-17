package com.devsentinel.service;

import com.devsentinel.client.AiAnalysisClient;
import com.devsentinel.dto.AiPredictResponse;
import com.devsentinel.dto.CodeSnippet;
import com.devsentinel.exception.JavaParseException;
import com.devsentinel.model.AnalysisRecord;
import com.devsentinel.model.VulnerabilityFinding;
import com.devsentinel.repository.AnalysisRecordRepository;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * Orchestrates one full analysis run.
 *
 * Pipeline:
 *   1. Parse the source into an AST (JavaParser).
 *   2. Run the static rule engine — always, and entirely offline.
 *   3. Extract method snippets and ask the Python AI service to score them.
 *   4. Merge the two result sets (see {@link #mergeFindings}).
 *   5. Persist the record plus its findings.
 *
 * Step 2 runs before step 3 and never depends on it, which is precisely why
 * the application still produces useful output in degraded mode.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AnalysisService {

    private static final String ENGINE_VERSION = "devsentinel-1.0.0";

    private final StaticRuleEngine staticRuleEngine;
    private final AiAnalysisClient aiAnalysisClient;
    private final AnalysisRecordRepository analysisRecordRepository;

    @Value("${devsentinel.ai.max-snippets:25}")
    private int maxSnippets;

    /**
     * Analyses one uploaded Java source file and persists the result.
     *
     * @param fileName    original upload name
     * @param sourceBytes raw file bytes
     * @return the saved {@link AnalysisRecord}, including all findings
     */
    @Transactional
    public AnalysisRecord analyse(String fileName, byte[] sourceBytes) {
        String sourceCode = new String(sourceBytes, StandardCharsets.UTF_8);
        CompilationUnit cu = parse(fileName, sourceCode);

        // --- 1. Static rules: always run, no network involved ---------------
        List<VulnerabilityFinding> staticFindings = staticRuleEngine.analyse(cu, fileName);

        // --- 2. AI pass: best-effort ----------------------------------------
        List<CodeSnippet> snippets = staticRuleEngine.extractMethodSnippets(cu);
        List<CodeSnippet> toScore = snippets.size() > maxSnippets
                ? snippets.subList(0, maxSnippets)
                : snippets;

        List<AiPredictResponse> aiResponses = aiAnalysisClient.predictAll(toScore);

        // The run is degraded when the client had to fall back for every
        // snippet it attempted (i.e. the service was genuinely unreachable).
        boolean degraded = !toScore.isEmpty()
                && aiResponses.stream().allMatch(AiPredictResponse::isFallback);

        // --- 3. Merge -------------------------------------------------------
        List<VulnerabilityFinding> merged =
                mergeFindings(staticFindings, aiResponses, toScore, fileName);

        // --- 4. Build and persist -------------------------------------------
        AnalysisRecord record = AnalysisRecord.builder()
                .fileName(fileName)
                .fileSizeBytes(sourceBytes.length)
                .checksumSha256(sha256(sourceBytes))
                .methodsAnalysed(snippets.size())
                .aiEngineStatus(degraded ? "DEGRADED" : "SUCCESS")
                .engineVersion(ENGINE_VERSION)
                .build();

        merged.forEach(record::addFinding);
        applySummaryCounts(record, merged);

        AnalysisRecord saved = analysisRecordRepository.save(record);
        log.info("Analysed '{}': {} findings ({} methods, AI status {})",
                fileName, saved.getTotalFindings(), saved.getMethodsAnalysed(),
                saved.getAiEngineStatus());
        return saved;
    }

    @Transactional(readOnly = true)
    public Optional<AnalysisRecord> findById(Long id) {
        return analysisRecordRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public List<AnalysisRecord> recentAnalyses() {
        return analysisRecordRepository.findTop20ByOrderByAnalysedAtDesc();
    }

    // =======================================================================
    // Parsing
    // =======================================================================

    private CompilationUnit parse(String fileName, String sourceCode) {
        // A fresh JavaParser instance rather than StaticJavaParser: the static
        // variant is global mutable state and is not safe across concurrent
        // uploads.
        JavaParser parser = new JavaParser(
                new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17));

        ParseResult<CompilationUnit> result;
        try {
            result = parser.parse(sourceCode);
        } catch (Exception ex) {
            throw new JavaParseException(
                    "Could not parse '" + fileName + "'. Please upload a valid Java source file.", ex);
        }

        if (!result.isSuccessful() || result.getResult().isEmpty()) {
            String problem = result.getProblems().stream()
                    .findFirst()
                    .map(p -> p.getMessage())
                    .orElse("unknown syntax error");
            throw new JavaParseException(
                    "'" + fileName + "' is not valid Java source. First problem: " + problem);
        }

        return result.getResult().get();
    }

    // =======================================================================
    // Merging static + AI results
    // =======================================================================

    /**
     * Combines both result sets without double-reporting the same issue.
     *
     * Rule: if the AI service reports the same vulnerability type inside a
     * method where a static rule already fired, the two are treated as ONE
     * finding — the static line number is kept (it is exact) and the AI
     * confidence is adopted (it is the more informative score). Otherwise the
     * AI finding is added separately, attributed to the method's start line.
     */
    List<VulnerabilityFinding> mergeFindings(List<VulnerabilityFinding> staticFindings,
                                             List<AiPredictResponse> aiResponses,
                                             List<CodeSnippet> snippets,
                                             String fileName) {
        List<VulnerabilityFinding> merged = new ArrayList<>(staticFindings);

        for (int i = 0; i < aiResponses.size() && i < snippets.size(); i++) {
            AiPredictResponse ai = aiResponses.get(i);
            if (ai == null || !ai.hasFinding()) continue;

            CodeSnippet snippet = snippets.get(i);

            Optional<VulnerabilityFinding> corroborated = merged.stream()
                    .filter(f -> f.getVulnerabilityType().equalsIgnoreCase(ai.getVulnerabilityType()))
                    .filter(f -> withinMethod(f, snippet))
                    .findFirst();

            if (corroborated.isPresent()) {
                // Both engines agree: upgrade confidence, record joint attribution.
                VulnerabilityFinding existing = corroborated.get();
                existing.setDetectionSource("STATIC+AI");
                existing.setConfidence(Math.max(existing.getConfidence(), ai.getConfidence()));
                continue;
            }

            merged.add(fromAi(ai, snippet, fileName));
        }

        // Most serious first, then by line number, so the UI reads sensibly.
        merged.sort(Comparator
                .comparingInt((VulnerabilityFinding f) -> -VulnerabilityCatalog.severityWeight(f.getSeverity()))
                .thenComparing(f -> f.getLineNumber() == null ? 0 : f.getLineNumber()));

        return merged;
    }

    /** Is this static finding located inside the given method's line range? */
    private boolean withinMethod(VulnerabilityFinding finding, CodeSnippet snippet) {
        if (finding.getLineNumber() == null) return false;
        int line = finding.getLineNumber();
        return line >= snippet.getStartLine() && line <= snippet.getEndLine();
    }

    /** Converts an AI-only result into a persistable finding. */
    private VulnerabilityFinding fromAi(AiPredictResponse ai, CodeSnippet snippet, String fileName) {
        VulnerabilityCatalog.Meta meta = VulnerabilityCatalog.lookup(ai.getVulnerabilityType());

        // Prefer the catalog's severity band so Java and Python never disagree
        // in the UI; fall back to the model's numeric score for unknown types.
        String severity = VulnerabilityCatalog.isKnown(ai.getVulnerabilityType())
                ? meta.getSeverity()
                : scoreToSeverity(ai.getSeverityScore());

        return VulnerabilityFinding.builder()
                .vulnerabilityType(ai.getVulnerabilityType())
                .displayName(meta.getDisplayName())
                .severity(severity)
                .category(meta.getCategory())
                .owaspCategory(ai.getOwaspCategory() != null
                        ? ai.getOwaspCategory() : meta.getOwaspCategory())
                .fileName(fileName)
                .methodName(snippet.getMethodName())
                .lineNumber(snippet.getStartLine())
                .codeSnippet(truncate(snippet.getSourceCode(), 1500))
                .description(ai.getIssueDescription())
                .remediation(ai.getSuggestedFix())
                .confidence(ai.getConfidence())
                .detectionSource("AI")
                .build();
    }

    private String scoreToSeverity(double score) {
        if (score >= 8.0) return "CRITICAL";
        if (score >= 6.0) return "HIGH";
        if (score >= 3.0) return "MEDIUM";
        return "LOW";
    }

    // =======================================================================
    // Summary
    // =======================================================================

    private void applySummaryCounts(AnalysisRecord record, List<VulnerabilityFinding> findings) {
        record.setTotalFindings(findings.size());
        record.setCriticalCount(count(findings, "CRITICAL"));
        record.setHighCount(count(findings, "HIGH"));
        record.setMediumCount(count(findings, "MEDIUM"));
        record.setLowCount(count(findings, "LOW"));

        int weighted = findings.stream()
                .mapToInt(f -> VulnerabilityCatalog.severityWeight(f.getSeverity()))
                .sum();
        record.setRiskScore(Math.min(weighted, 100));
    }

    private int count(List<VulnerabilityFinding> findings, String severity) {
        return (int) findings.stream().filter(f -> severity.equals(f.getSeverity())).count();
    }

    private String sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(data));
        } catch (NoSuchAlgorithmException ex) {
            // SHA-256 is guaranteed present by the JDK specification.
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    private static String truncate(String text, int max) {
        if (text == null) return null;
        return text.length() <= max ? text : text.substring(0, max) + "\n// ... truncated";
    }
}
