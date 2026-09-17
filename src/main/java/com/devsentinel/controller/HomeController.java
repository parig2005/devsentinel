package com.devsentinel.controller;

import com.devsentinel.client.AiAnalysisClient;
import com.devsentinel.dto.AiServiceStatus;
import com.devsentinel.model.AnalysisRecord;
import com.devsentinel.service.AnalysisService;
import com.devsentinel.service.UploadValidator;
import com.devsentinel.service.VulnerabilityCatalog;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.IOException;

/**
 * Thymeleaf MVC controller — the browser-facing side of DevSentinel.
 *
 * Routes:
 *   GET  /              upload page
 *   POST /analyze       handle the upload and show results
 *   GET  /results/{id}  re-open a stored analysis
 *   GET  /history       recent analyses
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class HomeController {

    private final AnalysisService analysisService;
    private final UploadValidator uploadValidator;
    private final AiAnalysisClient aiAnalysisClient;

    @GetMapping("/")
    public String home(Model model) {
        model.addAttribute("aiStatus", aiAnalysisClient.checkStatus());
        model.addAttribute("catalog", VulnerabilityCatalog.all());
        return "index";
    }

    @PostMapping("/analyze")
    public String analyze(@RequestParam("file") MultipartFile file,
                          RedirectAttributes redirectAttributes,
                          Model model) {

        // Validation failures are user errors, not server errors: send the user
        // back to the form with a readable message rather than an error page.
        try {
            uploadValidator.validate(file);

            byte[] bytes = file.getBytes();
            uploadValidator.validateContent(bytes, file.getOriginalFilename());

            AnalysisRecord record = analysisService.analyse(file.getOriginalFilename(), bytes);
            return "redirect:/results/" + record.getId();

        } catch (com.devsentinel.exception.AnalysisException ex) {
            log.info("Upload rejected: {}", ex.getMessage());
            redirectAttributes.addFlashAttribute("errorMessage", ex.getMessage());
            return "redirect:/";

        } catch (IOException ex) {
            log.error("Could not read uploaded file", ex);
            redirectAttributes.addFlashAttribute("errorMessage",
                    "The uploaded file could not be read. Please try again.");
            return "redirect:/";
        }
    }

    @GetMapping("/results/{id}")
    public String results(@PathVariable Long id, Model model) {
        return analysisService.findById(id)
                .map(record -> {
                    model.addAttribute("record", record);
                    model.addAttribute("aiStatus", statusFor(record));
                    return "results";
                })
                .orElse("redirect:/");
    }

    @GetMapping("/history")
    public String history(Model model) {
        model.addAttribute("records", analysisService.recentAnalyses());
        model.addAttribute("aiStatus", aiAnalysisClient.checkStatus());
        return "history";
    }

    /**
     * The banner on a results page should reflect the AI status AT THE TIME OF
     * THE RUN, not the live status — otherwise restarting the Python service
     * would silently rewrite the history of a degraded analysis.
     */
    private AiServiceStatus statusFor(AnalysisRecord record) {
        if (record.isDegraded()) {
            return AiServiceStatus.offline(
                    "The AI service was unreachable during this analysis. "
                    + "Results below come from the static rule engine only.");
        }
        return AiServiceStatus.builder()
                .reachable(true)
                .modelLoaded(true)
                .modelName("semantic scoring applied")
                .detail("AI semantic confidence scoring was applied to this analysis.")
                .build();
    }
}
