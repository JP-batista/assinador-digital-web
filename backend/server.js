const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const path    = require('path');
const db      = require('./database');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// ─── CADASTRO ────────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res.status(400).json({ error: 'Username e password são obrigatórios.' });

    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding:  { type: 'spki',  format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    db.prepare('INSERT INTO users (username, password, public_key, private_key) VALUES (?, ?, ?, ?)')
      .run([username, password, publicKey, privateKey], function(err) {
          if (err) return res.status(400).json({ error: 'Usuário já existe.' });
          res.json({ message: 'Usuário cadastrado com sucesso!', userId: this.lastID });
      });
});

// ─── LOGIN ───────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
    db.get('SELECT id, username FROM users WHERE username = ? AND password = ?',
           [req.body.username, req.body.password],
           (err, user) => {
               if (!user) return res.status(401).json({ error: 'Credenciais inválidas.' });
               res.json({ message: 'Login realizado com sucesso.', userId: user.id, username: user.username });
           });
});

// ─── ASSINAR ─────────────────────────────────────────────────────────────────
app.post('/api/sign', (req, res) => {
    const { userId, text } = req.body;
    if (!userId || !text)
        return res.status(400).json({ error: 'userId e text são obrigatórios.' });

    db.get('SELECT private_key FROM users WHERE id = ?', [userId], (err, user) => {
        if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });

        const hash = crypto.createHash('sha256').update(text).digest('hex');

        const sign = crypto.createSign('SHA256');
        sign.update(text);
        const signature = sign.sign(user.private_key, 'hex');

        db.prepare('INSERT INTO signatures (user_id, original_text, text_hash, signature_hex) VALUES (?, ?, ?, ?)')
          .run([userId, text, hash, signature], function(err) {
              if (err) return res.status(500).json({ error: 'Erro ao salvar assinatura.' });
              res.json({ message: 'Documento assinado com sucesso!', signatureId: this.lastID, hash, signature });
          });
    });
});

// ─── VERIFICAR POR ID ────────────────────────────────────────────────────────
app.get('/api/verify/:id', (req, res) => {
    const Q = `SELECT s.id, s.original_text, s.signature_hex, s.created_at,
                      u.username, u.public_key
               FROM signatures s JOIN users u ON s.user_id = u.id
               WHERE s.id = ?`;

    db.get(Q, [req.params.id], (err, row) => {
        if (!row) {
            db.run('INSERT INTO logs (signature_id, is_valid) VALUES (?, ?)', [null, 0]);
            return res.status(404).json({ status: 'INVÁLIDA', reason: 'ID de assinatura não encontrado.' });
        }

        const verify = crypto.createVerify('SHA256');
        verify.update(row.original_text);
        const isValid = verify.verify(row.public_key, row.signature_hex, 'hex');

        db.run('INSERT INTO logs (signature_id, is_valid) VALUES (?, ?)', [row.id, isValid ? 1 : 0]);

        res.json({
            status: isValid ? 'VÁLIDA' : 'INVÁLIDA',
            signatureId: row.id,
            signatory: row.username,
            algorithm: 'RSA-SHA256',
            date: row.created_at,
            text: row.original_text,
        });
    });
});

// ─── VERIFICAR POR TEXTO + ASSINATURA ────────────────────────────────────────
app.post('/api/verify', (req, res) => {
    const { text, signature } = req.body;
    if (!text || !signature)
        return res.status(400).json({ error: 'text e signature são obrigatórios.' });

    const Q = `SELECT s.id, s.created_at, u.username, u.public_key
               FROM signatures s JOIN users u ON s.user_id = u.id
               WHERE s.signature_hex = ?`;

    db.get(Q, [signature], (err, row) => {
        if (!row) {
            db.run('INSERT INTO logs (signature_id, is_valid) VALUES (?, ?)', [null, 0]);
            return res.json({ status: 'INVÁLIDA', reason: 'Assinatura não encontrada no sistema.' });
        }

        const verify = crypto.createVerify('SHA256');
        verify.update(text);
        const isValid = verify.verify(row.public_key, signature, 'hex');

        db.run('INSERT INTO logs (signature_id, is_valid) VALUES (?, ?)', [row.id, isValid ? 1 : 0]);

        res.json({
            status: isValid ? 'VÁLIDA' : 'INVÁLIDA',
            signatureId: row.id,
            signatory: row.username,
            algorithm: 'RSA-SHA256',
            date: row.created_at,
        });
    });
});

// ─── LISTAR CHAVES PÚBLICAS ───────────────────────────────────────────────────
app.get('/api/users/keys', (req, res) => {
    db.all('SELECT id, username, created_at FROM users ORDER BY username ASC', [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Erro ao buscar usuários.' });
        res.json(rows || []);
    });
});

// ─── DOWNLOAD CHAVE PÚBLICA ───────────────────────────────────────────────────
app.get('/api/users/:id/download/public', (req, res) => {
    db.get('SELECT username, public_key FROM users WHERE id = ?', [req.params.id], (err, user) => {
        if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
        res.setHeader('Content-Type', 'application/x-pem-file');
        res.setHeader('Content-Disposition', `attachment; filename="${user.username}_public.pem"`);
        res.send(user.public_key);
    });
});

// ─── DOWNLOAD CHAVE PRIVADA (apenas o próprio usuário) ────────────────────────
app.get('/api/users/:id/download/private', (req, res) => {
    const { userId } = req.query;
    if (!userId || String(userId) !== String(req.params.id))
        return res.status(403).json({ error: 'Você só pode baixar sua própria chave privada.' });

    db.get('SELECT username, private_key FROM users WHERE id = ?', [req.params.id], (err, user) => {
        if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
        res.setHeader('Content-Type', 'application/x-pem-file');
        res.setHeader('Content-Disposition', `attachment; filename="${user.username}_private.pem"`);
        res.send(user.private_key);
    });
});

// ─── Bootstrap ───────────────────────────────────────────────────────────────
async function start() {
    await db.init();

    if (require.main === module) {
        const PORT = 3000;
        app.listen(PORT, () => console.log(`🚀 Servidor rodando em http://localhost:${PORT}`));
    }
}

start();
module.exports = { app, ready: start() };
