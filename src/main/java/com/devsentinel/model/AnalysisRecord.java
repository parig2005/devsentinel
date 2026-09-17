package com.devsentinel.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * One row per analysed file — the summary of a single analysis run.
 *
 * Maps to the `analysis_records` table, created automatically by Hibernate.
 */
@Entity
@Table(name = "analysis_records")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AnalysisRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "file_name", nullable = false, length = 255)
    private String fileName;

    @Column(name = "file_size_bytes", nullable = false)
    private Integer fileSizeBytes;

    /** SHA-256 of the uploaded bytes — identifies re-uploads of the same file. */
    @Column(name = "checksum_sha256", nullable = false, length = 64)
    private String checksumSha256;

    @Column(name = "total_findings", nullable = false)
    @Builder.Default
    private Integer totalFindings = 0;

    @Column(name = "critical_count", nullable = false)
    @Builder.Default
    private Integer criticalCount = 0;

    @Column(name = "high_count", nullable = false)
    @Builder.Default
    private Integer highCount = 0;

    @Column(name = "medium_count", nullable = false)
    @Builder.Default
    private Integer mediumCount = 0;

    @Column(name = "low_count", nullable = false)
    @Builder.Default
    private Integer lowCount = 0;

    /** Weighted 0–100 risk score derived from the findings. */
    @Column(name = "risk_score", nullable = false)
    @Builder.Default
    private Integer riskScore = 0;

    /**
     * SUCCESS  — the Python AI service responded and enriched the findings.
     * DEGRADED — the AI service was unreachable; static rules only.
     */
    @Column(name = "ai_engine_status", nullable = false, length = 20)
    @Builder.Default
    private String aiEngineStatus = "SUCCESS";

    @Column(name = "methods_analysed", nullable = false)
    @Builder.Default
    private Integer methodsAnalysed = 0;

    @Column(name = "engine_version", length = 50)
    private String engineVersion;

    @Column(name = "analysed_at", nullable = false, updatable = false)
    @Builder.Default
    private LocalDateTime analysedAt = LocalDateTime.now();

    @OneToMany(mappedBy = "analysisRecord", cascade = CascadeType.ALL,
               orphanRemoval = true, fetch = FetchType.EAGER)
    @Builder.Default
    private List<VulnerabilityFinding> findings = new ArrayList<>();

    /** Keeps both sides of the bidirectional relationship consistent. */
    public void addFinding(VulnerabilityFinding finding) {
        findings.add(finding);
        finding.setAnalysisRecord(this);
    }

    /** True when the AI service could not be reached for this run. */
    @Transient
    public boolean isDegraded() {
        return "DEGRADED".equals(aiEngineStatus);
    }
}
