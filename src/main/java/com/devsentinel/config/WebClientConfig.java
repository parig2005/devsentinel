package com.devsentinel.config;

import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Builds the WebClient used to reach the Python AI service.
 *
 * The timeouts matter for the demo: without a connect timeout, a stopped
 * Python service can leave the upload request hanging instead of falling back
 * to degraded mode quickly.
 */
@Configuration
public class WebClientConfig {

    @Bean
    public WebClient aiWebClient(
            @Value("${devsentinel.ai.base-url}") String baseUrl,
            @Value("${devsentinel.ai.connect-timeout-ms}") int connectTimeoutMs,
            @Value("${devsentinel.ai.response-timeout-seconds}") int responseTimeoutSeconds) {

        HttpClient httpClient = HttpClient.create()
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeoutMs)
                .responseTimeout(Duration.ofSeconds(responseTimeoutSeconds))
                .doOnConnected(conn -> conn
                        .addHandlerLast(new ReadTimeoutHandler(responseTimeoutSeconds, TimeUnit.SECONDS))
                        .addHandlerLast(new WriteTimeoutHandler(responseTimeoutSeconds, TimeUnit.SECONDS)));

        return WebClient.builder()
                .baseUrl(baseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                // Snippets can be large; raise the default 256 KB buffer.
                .codecs(c -> c.defaultCodecs().maxInMemorySize(2 * 1024 * 1024))
                .build();
    }
}
