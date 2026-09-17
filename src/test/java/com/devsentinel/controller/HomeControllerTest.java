package com.devsentinel.controller;

import com.devsentinel.client.AiAnalysisClient;
import com.devsentinel.dto.AiServiceStatus;
import com.devsentinel.model.AnalysisRecord;
import com.devsentinel.service.AnalysisService;
import com.devsentinel.service.UploadValidator;
import com.devsentinel.service.VulnerabilityCatalog;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Web-layer tests: routing, view resolution, and upload validation behaviour.
 */
@WebMvcTest(HomeController.class)
class HomeControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AnalysisService analysisService;

    @MockBean
    private AiAnalysisClient aiAnalysisClient;

    // Real validator — we want its actual rules exercised here.
    @MockBean
    private UploadValidator uploadValidator;

    @Test
    @DisplayName("GET / renders the upload page with AI status and catalog")
    void homePageRenders() throws Exception {
        when(aiAnalysisClient.checkStatus())
                .thenReturn(AiServiceStatus.offline("AI service not reachable."));

        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(view().name("index"))
                .andExpect(model().attributeExists("aiStatus"))
                .andExpect(model().attributeExists("catalog"));
    }

    @Test
    @DisplayName("successful upload redirects to the results page")
    void uploadRedirectsToResults() throws Exception {
        AnalysisRecord record = AnalysisRecord.builder()
                .id(42L)
                .fileName("Foo.java")
                .fileSizeBytes(20)
                .checksumSha256("abc")
                .build();

        when(analysisService.analyse(anyString(), any())).thenReturn(record);

        MockMultipartFile file = new MockMultipartFile(
                "file", "Foo.java", "text/plain",
                "public class Foo {}".getBytes(StandardCharsets.UTF_8));

        mockMvc.perform(multipart("/analyze").file(file))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/results/42"));
    }

    @Test
    @DisplayName("invalid upload redirects home with a flash error message")
    void invalidUploadRedirectsHomeWithMessage() throws Exception {
        org.mockito.Mockito.doThrow(
                        new com.devsentinel.exception.InvalidUploadException("Only .java files are supported."))
                .when(uploadValidator).validate(any());

        MockMultipartFile file = new MockMultipartFile(
                "file", "notes.txt", "text/plain", "hello".getBytes(StandardCharsets.UTF_8));

        mockMvc.perform(multipart("/analyze").file(file))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"))
                .andExpect(flash().attributeExists("errorMessage"));
    }

    @Test
    @DisplayName("results page renders a stored analysis")
    void resultsPageRenders() throws Exception {
        AnalysisRecord record = AnalysisRecord.builder()
                .id(7L)
                .fileName("Foo.java")
                .fileSizeBytes(20)
                .checksumSha256("abc")
                .aiEngineStatus("SUCCESS")
                .build();

        when(analysisService.findById(7L)).thenReturn(Optional.of(record));

        mockMvc.perform(get("/results/7"))
                .andExpect(status().isOk())
                .andExpect(view().name("results"))
                .andExpect(model().attributeExists("record"))
                .andExpect(model().attributeExists("aiStatus"));
    }

    @Test
    @DisplayName("results page for a degraded run exposes a DEGRADED status")
    void degradedRunShowsDegradedStatus() throws Exception {
        AnalysisRecord record = AnalysisRecord.builder()
                .id(8L)
                .fileName("Foo.java")
                .fileSizeBytes(20)
                .checksumSha256("abc")
                .aiEngineStatus("DEGRADED")
                .build();

        when(analysisService.findById(8L)).thenReturn(Optional.of(record));

        mockMvc.perform(get("/results/8"))
                .andExpect(status().isOk())
                .andExpect(model().attribute("aiStatus",
                        org.hamcrest.Matchers.hasProperty("label",
                                org.hamcrest.Matchers.equalTo("DEGRADED"))));
    }

    @Test
    @DisplayName("unknown report id redirects home instead of erroring")
    void unknownReportRedirectsHome() throws Exception {
        when(analysisService.findById(999L)).thenReturn(Optional.empty());

        mockMvc.perform(get("/results/999"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"));
    }

    @Test
    @DisplayName("history page renders the recent analyses list")
    void historyPageRenders() throws Exception {
        when(analysisService.recentAnalyses()).thenReturn(List.of());
        when(aiAnalysisClient.checkStatus())
                .thenReturn(AiServiceStatus.offline("not reachable"));

        mockMvc.perform(get("/history"))
                .andExpect(status().isOk())
                .andExpect(view().name("history"))
                .andExpect(model().attributeExists("records"));
    }
}
