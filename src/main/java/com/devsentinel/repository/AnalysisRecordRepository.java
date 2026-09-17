package com.devsentinel.repository;

import com.devsentinel.model.AnalysisRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AnalysisRecordRepository extends JpaRepository<AnalysisRecord, Long> {

    /** Most recent analyses first — powers the History page. */
    List<AnalysisRecord> findTop20ByOrderByAnalysedAtDesc();

    List<AnalysisRecord> findByFileNameOrderByAnalysedAtDesc(String fileName);
}
