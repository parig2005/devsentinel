package com.devsentinel.client;

import com.devsentinel.dto.AiPredictRequest;
import com.devsentinel.dto.AiPredictResponse;
import com.devsentinel.dto.AiServiceStatus;
import com.devsentinel.dto.CodeSnippet;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Talks to the Python AI service.
 *
 * Contract with the rest of the application: this class NEVER propagates a
 * network failure. If the Python service is slow, broken, or stopped entirely,
 * every method returns a well-formed fallback value instead of throwing. That
 * is what makes degraded mode work — the analysis continues with static rules
 * and the UI reports AI status as DEGRADED.
 */
@Slf4j
@Component
public class AiAnalysisClient {

    private static final String PREDICT_PATH = "/api/v1/predict";
    private static final String HEALTH_PATH = "/health";

    /** Bounded parallelism: protects the single-process Python service. */
    private static final int CONCURRENCY = 4;

    private final WebClient aiWebClient;
    private final Duration requestTimeout;
    private final int maxRetries;

    public AiAnalysisClient(
            WebClient aiWebClient,
            @Value("${devsentinel.ai.response-timeout-seconds}") int timeoutSeconds,
            @Value("${devsentinel.ai.max-retries}") int maxRetries) {
        this.aiWebClient = aiWebClient;
        this.requestTimeout = Duration.ofSeconds(timeoutSeconds);
        this.maxRetries = maxRetries;
    }

    /**
     * Scores one snippet.
     *
     * @return a Mono that always completes with a value — never an error signal.
     */
    public Mono<AiPredictResponse> predict(CodeSnippet snippet) {
        AiPredictRequest request = AiPredictRequest.builder()
                .className(snippet.getClassName())
                .methodName(snippet.getMethodName())
                .codeSnippet(snippet.getSourceCode())
                .startLine(snippet.getStartLine())
                .staticAnalysisHint(snippet.getStaticAnalysisHint())
                .build();

        return aiWebClient.post()
                .uri(PREDICT_PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .retrieve()
                .bodyToMono(AiPredictResponse.class)
                .timeout(requestTimeout)
                .retryWhen(Retry.backoff(maxRetries, Duration.ofMillis(400))
                        .maxBackoff(Duration.ofSeconds(2))
                        .jitter(0.3))
                .onErrorResume(ex -> {
                    log.warn("AI prediction failed for {}#{}: {}",
                            snippet.getClassName(), snippet.getMethodName(), ex.toString());
                    return Mono.just(AiPredictResponse.offlineFallback());
                });
    }

    /**
     * Scores many snippets with bounded concurrency.
     *
     * Order is preserved via flatMapSequential so result[i] corresponds to
     * snippet[i] — the analyser relies on that alignment.
     */
    public List<AiPredictResponse> predictAll(List<CodeSnippet> snippets) {
        if (snippets == null || snippets.isEmpty()) return List.of();

        return Flux.fromIterable(snippets)
                .flatMapSequential(this::predict, CONCURRENCY)
                .collectList()
                .onErrorReturn(snippets.stream()
                        .map(s -> AiPredictResponse.offlineFallback())
                        .toList())
                .blockOptional(requestTimeout.multipliedBy(snippets.size() + 1L))
                .orElseGet(() -> snippets.stream()
                        .map(s -> AiPredictResponse.offlineFallback())
                        .toList());
    }

    /**
     * Health probe used by the UI banner and by the analyser to decide whether
     * to bother calling /predict at all. Short timeout on purpose: when the
     * service is down the user should see the degraded banner immediately.
     */
    @SuppressWarnings("unchecked")
    public AiServiceStatus checkStatus() {
        try {
            Map<String, Object> body = aiWebClient.get()
                    .uri(HEALTH_PATH)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .timeout(Duration.ofSeconds(2))
                    .block();

            if (body == null) {
                return AiServiceStatus.offline("AI service returned an empty response.");
            }

            boolean modelLoaded = Boolean.TRUE.equals(body.get("modelLoaded"))
                    || Boolean.TRUE.equals(body.get("model_loaded"));
            String modelName = String.valueOf(
                    body.getOrDefault("modelName", body.getOrDefault("model_name", "unknown")));

            return AiServiceStatus.builder()
                    .reachable(true)
                    .modelLoaded(modelLoaded)
                    .modelName(modelName)
                    .detail(modelLoaded
                            ? "CodeBERT embeddings active for semantic confidence scoring."
                            : "AI service is running without transformer weights (rule-only mode).")
                    .build();

        } catch (Exception ex) {
            log.info("AI service health check failed: {}", ex.getMessage());
            return AiServiceStatus.offline(
                    "Python AI service is not reachable. Static rule analysis is still available.");
        }
    }
}
