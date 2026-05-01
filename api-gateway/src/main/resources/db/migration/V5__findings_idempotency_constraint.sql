ALTER TABLE findings
    ADD CONSTRAINT uq_finding_per_scan UNIQUE (scan_id, title, evidence);
