package com.devsentinel.client;

import com.devsentinel.dto.AiPredictResponse;
import com.devsentinel.dto.AiServiceStatus;
import com.devsentinel.dto.CodeSnippet;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.SocketPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the "never throw" contract of AiAnalysisClient using a real HTTP
 * server that we can break on purpose. This is the safety net behind the
 * degraded-mode behaviour demonstrated in the UI.
 */
class AiAnalysisClientTest {

    private MockWebServer server;
    private AiAnalysisClient client;

    private static final CodeSnippet SNIPPET = CodeSnippet.builder()
            .className("UserDao")
            .methodName("find")
            .sourceCode("public void find() {}")
            .startLine(1)
            .endLine(3)
            .build();

    @BeforeEach
    void setUp() throws IOException {
        server = new MockWebServer();
        server.start();
        WebClient webClient = WebClient.builder()
                .baseUrl(server.url("/").toString())
                .build();
        // maxRetries = 0 keeps the failure tests fast.
        client = new AiAnalysisClient(webClient, 2, 0);
    }

    @AfterEach
    void tearDown() throws IOException {
        server.shutdown();
    }

    @Test
    @DisplayName("parses a successful prediction response")
    void parsesSuccessfulResponse() {
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("""
                        {
                          "vulnerabilityType": "SQL_INJECTION",
                          "severityScore": 9.0,
                          "issueDescription": "Concatenated SQL",
                          "suggestedFix": "Use PreparedStatement",
                          "owaspCategory": "A03:2021-Injection",
                          "confidence": 0.91,
                          "modelVersion": "microsoft/codebert-base"
                        }
                        """));

        AiPredictResponse response = client.predict(SNIPPET).block();

        assertThat(response).isNotNull();
        assertThat(response.getVulnerabilityType()).isEqualTo("SQL_INJECTION");
        assertThat(response.getConfidence()).isEqualTo(0.91);
        assertThat(response.isFallback()).isFalse();
        assertThat(response.hasFinding()).isTrue();
    }

    @Test
    @DisplayName("returns a fallback instead of throwing on HTTP 500")
    void fallsBackOnServerError() {
        server.enqueue(new MockResponse().setResponseCode(500).setBody("boom"));

        AiPredictResponse response = client.predict(SNIPPET).block();

        assertThat(response).isNotNull();
        assertThat(response.isFallback()).isTrue();
        assertThat(response.hasFinding()).isFalse();
    }

    @Test
    @DisplayName("returns a fallback when the connection is dropped")
    void fallsBackOnDroppedConnection() {
        server.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START));

        AiPredictResponse response = client.predict(SNIPPET).block();

        assertThat(response).isNotNull();
        assertThat(response.isFallback()).isTrue();
    }

    @Test
    @DisplayName("returns a fallback when the service is completely down")
    void fallsBackWhenServiceDown() throws IOException {
        server.shutdown(); // nothing is listening any more

        AiPredictResponse response = client.predict(SNIPPET).block();

        assertThat(response).isNotNull();
        assertThat(response.isFallback()).isTrue();
    }

    @Test
    @DisplayName("predictAll returns one fallback per snippet when the service is down")
    void predictAllFallsBackForEverySnippet() throws IOException {
        server.shutdown();

        List<AiPredictResponse> responses = client.predictAll(List.of(SNIPPET, SNIPPET, SNIPPET));

        assertThat(responses).hasSize(3);
        assertThat(responses).allMatch(AiPredictResponse::isFallback);
    }

    @Test
    @DisplayName("predictAll preserves snippet order")
    void predictAllPreservesOrder() {
        for (String type : List.of("SQL_INJECTION", "HARDCODED_SECRET", "NONE")) {
            server.enqueue(new MockResponse()
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"vulnerabilityType\":\"" + type + "\",\"severityScore\":1.0,"
                            + "\"issueDescription\":\"x\",\"confidence\":0.5}"));
        }

        List<AiPredictResponse> responses = client.predictAll(List.of(SNIPPET, SNIPPET, SNIPPET));

        assertThat(responses).extracting(AiPredictResponse::getVulnerabilityType)
                .containsExactly("SQL_INJECTION", "HARDCODED_SECRET", "NONE");
    }

    @Test
    @DisplayName("checkStatus reports ONLINE when the model is loaded")
    void checkStatusOnline() {
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("{\"status\":\"UP\",\"modelLoaded\":true,"
                        + "\"modelName\":\"microsoft/codebert-base\",\"device\":\"cpu\"}"));

        AiServiceStatus status = client.checkStatus();

        assertThat(status.isReachable()).isTrue();
        assertThat(status.isModelLoaded()).isTrue();
        assertThat(status.getLabel()).isEqualTo("ONLINE");
    }

    @Test
    @DisplayName("checkStatus reports rule-only when weights are absent")
    void checkStatusRuleOnly() {
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("{\"status\":\"UP\",\"modelLoaded\":false,\"modelName\":\"rule-only\"}"));

        AiServiceStatus status = client.checkStatus();

        assertThat(status.isReachable()).isTrue();
        assertThat(status.isModelLoaded()).isFalse();
        assertThat(status.getLabel()).contains("rule-only");
    }

    @Test
    @DisplayName("checkStatus reports DEGRADED when the service is unreachable")
    void checkStatusDegraded() throws IOException {
        server.shutdown();

        AiServiceStatus status = client.checkStatus();

        assertThat(status.isReachable()).isFalse();
        assertThat(status.getLabel()).isEqualTo("DEGRADED");
        assertThat(status.getCssClass()).isEqualTo("status-degraded");
    }

    @Test
    @DisplayName("empty snippet list short-circuits without any HTTP call")
    void emptyListMakesNoCalls() {
        assertThat(client.predictAll(List.of())).isEmpty();
        assertThat(server.getRequestCount()).isZero();
    }
}
