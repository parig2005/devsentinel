-- ===========================================================================
-- DevSentinel — PostgreSQL schema
--
-- YOU DO NOT NEED THIS FILE FOR THE DEFAULT SETUP.
-- With H2 (the default) Hibernate creates these tables automatically on the
-- first run. This script exists for two cases:
--   1. You chose the 'postgres' profile and prefer explicit DDL over ddl-auto.
--   2. Your examiner asks to see the relational design as SQL.
--
-- Usage:
--   createdb devsentinel
--   psql -d devsentinel -f db/schema.sql
-- ===========================================================================

DROP TABLE IF EXISTS vulnerability_findings CASCADE;
DROP TABLE IF EXISTS analysis_records CASCADE;

-- ---------------------------------------------------------------------------
-- analysis_records — one row per analysed file (the summary of a run)
-- ---------------------------------------------------------------------------
CREATE TABLE analysis_records (
    id                BIGSERIAL PRIMARY KEY,
    file_name         VARCHAR(255) NOT NULL,
    file_size_bytes   INTEGER      NOT NULL,
    checksum_sha256   VARCHAR(64)  NOT NULL,
    total_findings    INTEGER      NOT NULL DEFAULT 0,
    critical_count    INTEGER      NOT NULL DEFAULT 0,
    high_count        INTEGER      NOT NULL DEFAULT 0,
    medium_count      INTEGER      NOT NULL DEFAULT 0,
    low_count         INTEGER      NOT NULL DEFAULT 0,
    risk_score        INTEGER      NOT NULL DEFAULT 0,
    methods_analysed  INTEGER      NOT NULL DEFAULT 0,

    -- SUCCESS  = the Python AI service responded and enriched the findings
    -- DEGRADED = the AI service was unreachable; static rules only
    ai_engine_status  VARCHAR(20)  NOT NULL DEFAULT 'SUCCESS',

    engine_version    VARCHAR(50),
    analysed_at       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_ai_engine_status
        CHECK (ai_engine_status IN ('SUCCESS', 'DEGRADED')),
    CONSTRAINT chk_risk_score
        CHECK (risk_score >= 0 AND risk_score <= 100)
);

-- Powers the History page ("most recent 20 analyses").
CREATE INDEX idx_analysis_records_analysed_at ON analysis_records (analysed_at DESC);
-- Detects re-uploads of an identical file.
CREATE INDEX idx_analysis_records_checksum    ON analysis_records (checksum_sha256);

-- ---------------------------------------------------------------------------
-- vulnerability_findings — one row per detected issue
-- ---------------------------------------------------------------------------
CREATE TABLE vulnerability_findings (
    id                  BIGSERIAL PRIMARY KEY,
    analysis_record_id  BIGINT       NOT NULL,

    vulnerability_type  VARCHAR(100) NOT NULL,  -- SQL_INJECTION, HARDCODED_SECRET, ...
    display_name        VARCHAR(120) NOT NULL,  -- "SQL Injection"
    severity            VARCHAR(20)  NOT NULL,  -- CRITICAL | HIGH | MEDIUM | LOW
    category            VARCHAR(30)  NOT NULL,  -- SECURITY | PERFORMANCE | LOGIC
    owasp_category      VARCHAR(80),            -- "A03:2021-Injection", nullable

    file_name           VARCHAR(255),
    method_name         VARCHAR(150),
    line_number         INTEGER,

    code_snippet        VARCHAR(4000),
    description         VARCHAR(2000) NOT NULL,
    remediation         VARCHAR(4000),

    -- 0.0-1.0. Rule confidence for STATIC findings, CodeBERT semantic
    -- similarity when the AI service supplied a score.
    confidence          DOUBLE PRECISION NOT NULL DEFAULT 0.0,

    -- STATIC | AI | STATIC+AI  (STATIC+AI means both engines agreed)
    detection_source    VARCHAR(20)  NOT NULL DEFAULT 'STATIC',

    created_at          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_findings_analysis
        FOREIGN KEY (analysis_record_id)
        REFERENCES analysis_records (id) ON DELETE CASCADE,

    CONSTRAINT chk_severity
        CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    CONSTRAINT chk_category
        CHECK (category IN ('SECURITY', 'PERFORMANCE', 'LOGIC')),
    CONSTRAINT chk_detection_source
        CHECK (detection_source IN ('STATIC', 'AI', 'STATIC+AI')),
    CONSTRAINT chk_confidence
        CHECK (confidence >= 0.0 AND confidence <= 1.0)
);

CREATE INDEX idx_findings_analysis_id ON vulnerability_findings (analysis_record_id);
CREATE INDEX idx_findings_severity    ON vulnerability_findings (severity);
CREATE INDEX idx_findings_type        ON vulnerability_findings (vulnerability_type);

-- ---------------------------------------------------------------------------
-- Useful queries for the viva ("show me the data is really persisted")
-- ---------------------------------------------------------------------------

-- Every analysis with its finding count:
--   SELECT id, file_name, total_findings, risk_score, ai_engine_status, analysed_at
--   FROM analysis_records ORDER BY analysed_at DESC;

-- All findings for the most recent run:
--   SELECT vulnerability_type, severity, line_number, confidence, detection_source
--   FROM vulnerability_findings
--   WHERE analysis_record_id = (SELECT MAX(id) FROM analysis_records)
--   ORDER BY severity;

-- How many runs happened in degraded mode:
--   SELECT ai_engine_status, COUNT(*) FROM analysis_records GROUP BY ai_engine_status;
