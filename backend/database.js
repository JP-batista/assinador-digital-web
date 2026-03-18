const initSqlJs = require('sql.js');
const fs        = require('fs');
const path      = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'database.db');

// sql.js trabalha em memória; persistimos manualmente em arquivo
let db;
let sqlJs;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    private_key TEXT NOT NULL,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS signatures (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    original_text TEXT NOT NULL,
    text_hash     TEXT NOT NULL,
    signature_hex TEXT NOT NULL,
    created_at    TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    signature_id INTEGER,
    is_valid     INTEGER NOT NULL,
    checked_at   TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(signature_id) REFERENCES signatures(id)
);
`;

function save() {
    if (DB_PATH === ':memory:') return;
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
}

async function init() {
    sqlJs = await initSqlJs();

    if (DB_PATH !== ':memory:' && fs.existsSync(DB_PATH)) {
        const fileBuffer = fs.readFileSync(DB_PATH);
        db = new sqlJs.Database(fileBuffer);
    } else {
        db = new sqlJs.Database();
    }

    db.run(SCHEMA);
    save();
    return db;
}

// ─── Wrappers com API semelhante ao sqlite3 callback ─────────────────────────

function prepare(sql) {
    return {
        run(params, cb) {
            try {
                db.run(sql, params);
                // lastID via SELECT last_insert_rowid()
                const stmt = db.prepare('SELECT last_insert_rowid() as id');
                stmt.step();
                const row = stmt.getAsObject();
                stmt.free();
                save();
                if (cb) cb.call({ lastID: row.id }, null);
            } catch (err) {
                if (cb) cb.call({}, err);
            }
        }
    };
}

function get(sql, params, cb) {
    try {
        const stmt = db.prepare(sql);
        stmt.bind(params);
        const rows = [];
        while (stmt.step()) rows.push(stmt.getAsObject());
        stmt.free();
        if (cb) cb(null, rows[0] || undefined);
    } catch (err) {
        if (cb) cb(err, undefined);
    }
}

function all(sql, params, cb) {
    try {
        const stmt = db.prepare(sql);
        stmt.bind(params);
        const rows = [];
        while (stmt.step()) rows.push(stmt.getAsObject());
        stmt.free();
        if (cb) cb(null, rows);
    } catch (err) {
        if (cb) cb(err, []);
    }
}

function run(sql, params, cb) {
    try {
        db.run(sql, params || []);
        save();
        if (cb) cb(null);
    } catch (err) {
        if (cb) cb(err);
    }
}

module.exports = { init, prepare, get, all, run };
