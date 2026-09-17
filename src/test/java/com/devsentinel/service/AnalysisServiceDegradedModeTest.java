package com.devsentinel.service;

import com.devsentinel.client.AiAnalysisClient;
import com.devsentinel.dto.AiPredictResponse;
import com.devsentinel.dto.CodeSnippet;
import com.devsentinel.model.AnalysisRecord;
import com.devsentinel.model.VulnerabilityFinding;
import com.devsentinel.repository.AnalysisRecordRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.when;

/**
 * The degraded-mode contract: when the Python AI service is unreachable, the
 * analysis must still succeed using static rules and be marked DEGRADED.
 */
@ExtendWith(MockitoExtension.class)
class AnalysisServiceDegradedModeTest {

    @Spy
    private StaticRuleEngine staticRuleEngine = new StaticRuleEngine();

    @Mock
    private AiAnalysisClient aiAnalysisClient;

    @Mock
    private AnalysisRecordRepository analysisRecordRepository;

    @InjectMocks
    private AnalysisService analysisService;

    private static final String VULNERABLE_SOURCE = """
            public class UserDao {
                private String dbPassword = "secret123";

                public void find(String name) throws Exception {
                    Statement stmt = conn.createStatement();
                    stmt.executeQuery("SELECT * FROM users WHERE name='" + name + "'");
                }
            }
            """;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(analysisService, "maxSnippets", 25);
        // save() returns its argument so the test can inspect the built record.
        when(analysisRecordRepository.save(org.mockito.ArgumentMatchers.any(AnalysisRecord.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    @DisplayName("AI service offline: analysis still succeeds and is marked DEGRADED")
    void degradesGracefullyWhenAiOffline() {
        // Simulate total AI failure — every snippet returns the offline fallback.
        when(aiAnalysisClient.predictAll(anyList()))
                .thenAnswer(inv -> ((List<CodeSnippet>) inv.getArgument(0)).stream()
                        .map(s -> AiPredictResponse.offlineFallback())
                        .toList());

        AnalysisRecord record = analysisService.analyse(
                "UserDao.java", VULNERABLE_SOURCE.getBytes(StandardCharsets.UTF_8));

        assertThat(record.getAiEngineStatus()).isEqualTo("DEGRADED");
        assertThat(record.isDegraded()).isTrue();

        // Crucially: static findings are still present.
        assertThat(record.getTotalFindings()).isGreaterThan(0);
        assertThat(record.getFindings())
                .extracting(VulnerabilityFinding::getVulnerabilityType)
                .contains("SQL_INJECTION", "HARDCODED_SECRET");

        // No finding should claim AI attribution when AI never responded.
        assertThat(record.getFindings())
                .extracting(VulnerabilityFinding::getDetectionSource)
                .containsOnly("STATIC");
    }

    @Test
    @DisplayName("AI service online: run is marked SUCCESS and confidence is adopted")
    void marksSuccessWhenAiResponds() {
        when(aiAnalysisClient.predictAll(anyList()))
                .thenAnswer(inv -> ((List<CodeSnippet>) inv.getArgument(0)).stream()
                        .map(s -> AiPredictResponse.builder()
                                .vulnerabilityType("SQL_INJECTION")
                                .severityScore(9.0)
                                .issueDescription("Concatenated SQL")
                                .suggestedFix("Use PreparedStatement")
                                .owaspCategory("A03:2021-Injection")
                                .confidence(0.93)
                                .modelVersion("microsoft/codebert-base")
                                .fallback(false)
                                .build())
                        .toList());

        AnalysisRecord record = analysisService.analyse(
                "UserDao.java", VULNERABLE_SOURCE.getBytes(StandardCharsets.UTF_8));

        assertThat(record.getAiEngineStatus()).isEqualTo("SUCCESS");

        // Both engines found SQL injection in the same method, so it must be
        // reported ONCE, with joint attribution and the AI confidence.
        List<VulnerabilityFinding> sqlFindings = record.getFindings().stream()
                .filter(f -> "SQL_INJECTION".equals(f.getVulnerabilityType()))
                .toList();

        assertThat(sqlFindings).hasSize(1);
        assertThat(sqlFindings.get(0).getDetectionSource()).isEqualTo("STATIC+AI");
        assertThat(sqlFindings.get(0).getConfidence()).isEqualTo(0.93);
    }

    @Test
    @DisplayName("summary counts and risk score are computed from the findings")
    void computesSummaryCounts() {
        when(aiAnalysisClient.predictAll(anyList()))
                .thenAnswer(inv -> ((List<CodeSnippet>) inv.getArgument(0)).stream()
                        .map(s -> AiPredictResponse.offlineFallback())
                        .toList());

        AnalysisRecord record = analysisService.analyse(
                "UserDao.java", VULNERABLE_SOURCE.getBytes(StandardCharsets.UTF_8));

        int summed = record.getCriticalCount() + record.getHighCount()
                + record.getMediumCount() + record.getLowCount();

        assertThat(summed).isEqualTo(record.getTotalFindings());
        assertThat(record.getRiskScore()).isGreaterThan(0).isLessThanOrEqualTo(100);
        assertThat(record.getChecksumSha256()).hasSize(64);
        assertThat(record.getMethodsAnalysed()).isGreaterThan(0);
    }

    @Test
    @DisplayName("findings are ordered most severe first")
    void ordersFindingsBySeverity() {
        when(aiAnalysisClient.predictAll(anyList()))
                .thenAnswer(inv -> ((List<CodeSnippet>) inv.getArgument(0)).stream()
                        .map(s -> AiPredictResponse.offlineFallback())
                        .toList());

        AnalysisRecord record = analysisService.analyse(
                "UserDao.java", VULNERABLE_SOURCE.getBytes(StandardCharsets.UTF_8));

        List<Integer> weights = record.getFindings().stream()
                .map(f -> VulnerabilityCatalog.severityWeight(f.getSeverity()))
                .toList();

        assertThat(weights).isSortedAccordingTo(java.util.Comparator.reverseOrder());
    }
}
