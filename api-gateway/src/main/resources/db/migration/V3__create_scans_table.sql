-- Scans table — for each scan started for a domain
CREATE TABLE scans (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id   UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- QUEUED → RUNNING → COMPLETED veya FAILED
    status      VARCHAR(50)  NOT NULL DEFAULT 'QUEUED',
    -- 0-100 progress percentage
    progress    INTEGER      NOT NULL DEFAULT 0,
    started_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    finished_at TIMESTAMP WITH TIME ZONE
);
