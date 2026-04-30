-- Domains table — for user owned and verified domains
CREATE TABLE domains (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                VARCHAR(255) NOT NULL,
    -- DNS TXT record verification token
    verification_token  VARCHAR(255) NOT NULL,
    -- PENDING: token generated, VERIFIED: DNS verified
    status              VARCHAR(50)  NOT NULL DEFAULT 'PENDING',
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    verified_at         TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, name)
);
