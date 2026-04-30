-- Findings table — for each security finding in a scan
CREATE TABLE findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    severity        VARCHAR(50)  NOT NULL,
    -- OWASP Top 10 category 
    owasp_category  VARCHAR(100),
    title           VARCHAR(255) NOT NULL,
    description     TEXT,
    -- Finding evidence — request/response or screenshot path
    evidence        TEXT,
    -- How to fix
    remediation     TEXT,
    -- CVSS 3.1 base score — 0.0 to 10.0
    cvss_score      DECIMAL(3, 1),
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Scan index to speed up finding queries
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
-- Severity index to filter by severity
CREATE INDEX idx_findings_severity ON findings(severity);
