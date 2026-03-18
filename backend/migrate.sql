-- =============================================================================
-- Assinador Digital Web — Schema do Banco de Dados (SQLite)
-- =============================================================================

CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT UNIQUE NOT NULL,
    password     TEXT NOT NULL,
    public_key   TEXT NOT NULL,
    private_key  TEXT NOT NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS signatures (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL,
    original_text  TEXT NOT NULL,
    text_hash      TEXT NOT NULL,        -- SHA-256 hex do texto original
    signature_hex  TEXT NOT NULL,        -- assinatura RSA em hexadecimal
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    signature_id INTEGER,               -- NULL se assinatura não encontrada
    is_valid     INTEGER NOT NULL,      -- 1 = válida, 0 = inválida
    checked_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(signature_id) REFERENCES signatures(id)
);
