-- Authentication & authorization. See CLAUDE.md → "Phase 2.0 — Auth + TOTP".
-- All tables use IF NOT EXISTS so re-running this migration on a populated DB
-- is a no-op (in addition to the runner's tracking).

CREATE TABLE IF NOT EXISTS users (
    id                 uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    username           text                     NOT NULL UNIQUE,
    email              text,
    password_hash      text                     NOT NULL,            -- argon2id encoded string
    role               text                     NOT NULL DEFAULT 'viewer',
    is_active          boolean                  NOT NULL DEFAULT true,
    failed_login_count int                      NOT NULL DEFAULT 0,
    locked_until       timestamp with time zone,
    last_login_at      timestamp with time zone,
    last_login_ip      inet,
    created_at         timestamp with time zone NOT NULL DEFAULT now(),
    updated_at         timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT users_role_chk CHECK (role IN ('admin', 'operator', 'viewer'))
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- TOTP secrets — one per user; encrypted with the daemon-held master key.
-- Layout: 12-byte nonce || 16-byte tag || ciphertext (AES-256-GCM).
CREATE TABLE IF NOT EXISTS user_totp_secrets (
    user_id          uuid                     PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_encrypted bytea                    NOT NULL,
    enrolled_at      timestamp with time zone NOT NULL DEFAULT now(),
    last_used_at     timestamp with time zone,
    last_used_step   bigint                                          -- TOTP step counter (anti-replay)
);

-- Recovery codes — single-use, hashed (argon2). Hand out 10 at enrollment.
CREATE TABLE IF NOT EXISTS user_recovery_codes (
    id         uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id    uuid                     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  text                     NOT NULL,
    used_at    timestamp with time zone,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_recovery_codes_user_unused
    ON user_recovery_codes(user_id) WHERE used_at IS NULL;

-- Server-side sessions. The cookie carries an opaque token; only its SHA-256
-- hash is stored, so DB-read access does NOT equal session takeover.
CREATE TABLE IF NOT EXISTS user_sessions (
    id             uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id        uuid                     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash     text                     NOT NULL UNIQUE,         -- sha256(cookie value), hex
    auth_level     text                     NOT NULL DEFAULT 'basic',
    elevated_until timestamp with time zone,
    created_at     timestamp with time zone NOT NULL DEFAULT now(),
    expires_at     timestamp with time zone NOT NULL,
    last_seen_at   timestamp with time zone NOT NULL DEFAULT now(),
    ip             inet,
    user_agent     text,
    revoked_at     timestamp with time zone,
    CONSTRAINT user_sessions_level_chk CHECK (auth_level IN ('basic', 'elevated'))
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_active
    ON user_sessions(user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_expires
    ON user_sessions(expires_at) WHERE revoked_at IS NULL;

-- Auth audit log — separate from fw_audit_log so a firewall-side compromise
-- can't tamper with the auth trail. Append-only by convention.
CREATE TABLE IF NOT EXISTS auth_audit_log (
    id          bigserial                PRIMARY KEY,
    occurred_at timestamp with time zone NOT NULL DEFAULT now(),
    user_id     uuid                                 REFERENCES users(id) ON DELETE SET NULL,
    username    text,                                                -- captured for forensics
    event_type  text                     NOT NULL,                   -- login.success, totp.verified, etc.
    ip          inet,
    user_agent  text,
    detail      jsonb
);

CREATE INDEX IF NOT EXISTS idx_auth_audit_time  ON auth_audit_log(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_audit_user  ON auth_audit_log(user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_audit_event ON auth_audit_log(event_type, occurred_at DESC);
