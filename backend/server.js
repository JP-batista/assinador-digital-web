const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const db = require('./database');

const app = express();

app.use(cors());
app.use(express.json());

app.use(express.static(path.join(__dirname, '../frontend')));

app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const stmt = db.prepare("INSERT INTO users (username, password, public_key, private_key) VALUES (?, ?, ?, ?)");
    stmt.run([username, password, publicKey, privateKey], function(err) {
        if (err) return res.status(400).json({ error: "Usuário já existe ou erro no banco." });
        res.json({ message: "Usuário cadastrado com sucesso!", userId: this.lastID });
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT id, username FROM users WHERE username = ? AND password = ?", [username, password], (err, user) => {
        if (!user) return res.status(401).json({ error: "Credenciais inválidas" });
        res.json({ message: "Login sucesso", userId: user.id });
    });
});

app.post('/api/sign', (req, res) => {
    const { userId, text } = req.body;
    db.get("SELECT private_key FROM users WHERE id = ?", [userId], (err, user) => {
        if (!user) return res.status(404).json({ error: "Usuário não encontrado" });

        const sign = crypto.createSign('SHA256');
        sign.update(text);
        const signature = sign.sign(user.private_key, 'hex');

        const stmt = db.prepare("INSERT INTO signatures (user_id, original_text, signature_hash) VALUES (?, ?, ?)");
        stmt.run([userId, text, signature], function(err) {
            res.json({ message: "Documento assinado!", signature: signature });
        });
    });
});

app.post('/api/verify', (req, res) => {
    const { text, signature } = req.body;
    const query = `
        SELECT s.id as sig_id, s.created_at, u.username, u.public_key 
        FROM signatures s
        JOIN users u ON s.user_id = u.id
        WHERE s.signature_hash = ?
    `;

    db.get(query, [signature], (err, row) => {
        if (!row) {
            db.run("INSERT INTO logs (signature_id, is_valid) VALUES (?, ?)", [null, false]);
            return res.json({ status: "INVÁLIDA", reason: "Assinatura corrompida ou inexistente." });
        }

        const verify = crypto.createVerify('SHA256');
        verify.update(text);
        const isValid = verify.verify(row.public_key, signature, 'hex');

        db.run("INSERT INTO logs (signature_id, is_valid) VALUES (?, ?)", [row.sig_id, isValid]);

        res.json({
            status: isValid ? "VÁLIDA" : "INVÁLIDA",
            signatory: row.username,
            algorithm: "SHA-256 / RSA",
            date: row.created_at
        });
    });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando! Acesse: http://localhost:${PORT}`);
});