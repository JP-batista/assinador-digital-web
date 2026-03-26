const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const path    = require('path');
const db      = require('./database');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

function buildSignedMessageFile({ signatureId, userId, username, text, hash, signature, signedAt, mode }) {
    return {
        filename: `assinatura-${signatureId}.adsig.json`,
        payload: {
            version: 1,
            mode,
            algorithm: 'RSA-SHA256',
            signatureId,
            signerUserId: userId,
            signerUsername: username,
            signedAt,
            message: text,
            hash,
            signature,
        },
    };
}

function buildPublicKeyMessageFile({ senderUserId, senderUsername, recipientUserId, recipientUsername, encryptedMessage, signedAt }) {
    return {
        filename: `mensagem-publica-${recipientUsername}-${Date.now()}.adsig.json`,
        payload: {
            version: 1,
            mode: 'public_key',
            algorithm: 'RSA-OAEP-SHA256',
            senderUserId,
            senderUsername,
            recipientUserId,
            recipientUsername,
            signedAt,
            encryptedMessage,
        },
    };
}

function verifyPrivateKeyFile(payload, publicKeyPem) {
    const hash = crypto.createHash('sha256').update(payload.message).digest('hex');

    if (hash !== payload.hash) {
        return { ok: false, error: 'O hash do arquivo não confere com a mensagem.' };
    }

    const verify = crypto.createVerify('SHA256');
    verify.update(payload.message);
    const isValid = verify.verify(publicKeyPem, payload.signature, 'hex');

    if (!isValid) {
        return { ok: false, error: 'A assinatura não confere com a chave pública informada.' };
    }

    return {
        ok: true,
        data: {
            mode: payload.mode,
            algorithm: payload.algorithm,
            message: payload.message,
            signatureId: payload.signatureId,
            signerUsername: payload.signerUsername,
            signedAt: payload.signedAt,
            status: 'VÁLIDA',
        },
    };
}

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

    db.get('SELECT username, private_key FROM users WHERE id = ?', [userId], (err, user) => {
        if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });

        const hash = crypto.createHash('sha256').update(text).digest('hex');

        const sign = crypto.createSign('SHA256');
        sign.update(text);
        const signature = sign.sign(user.private_key, 'hex');

        db.prepare('INSERT INTO signatures (user_id, original_text, text_hash, signature_hex) VALUES (?, ?, ?, ?)')
          .run([userId, text, hash, signature], function(err) {
              if (err) return res.status(500).json({ error: 'Erro ao salvar assinatura.' });
              const signedFile = buildSignedMessageFile({
                  signatureId: this.lastID,
                  userId,
                  username: user.username,
                  text,
                  hash,
                  signature,
                  signedAt: new Date().toISOString(),
                  mode: 'private_key',
              });

              res.json({
                  message: 'Documento assinado com sucesso!',
                  signatureId: this.lastID,
                  hash,
                  signature,
                  signedFile,
              });
          });
    });
});

app.post('/api/sign/public', (req, res) => {
    const { senderUserId, publicKeyPem, text } = req.body;
    if (!senderUserId || !publicKeyPem || !text)
        return res.status(400).json({ error: 'senderUserId, publicKeyPem e text são obrigatórios.' });

    db.get('SELECT id, username FROM users WHERE id = ?', [senderUserId], (err, sender) => {
        if (!sender) return res.status(404).json({ error: 'Usuário remetente não encontrado.' });

        let encryptedMessage;
        try {
            encryptedMessage = crypto.publicEncrypt(
                {
                    key: publicKeyPem,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: 'sha256',
                },
                Buffer.from(text, 'utf8')
            ).toString('base64');
        } catch {
            return res.status(400).json({ error: 'Chave pública inválida ou incompatível.' });
        }

        const signedFile = buildPublicKeyMessageFile({
            senderUserId: sender.id,
            senderUsername: sender.username,
            recipientUserId: null,
            recipientUsername: null,
            encryptedMessage,
            signedAt: new Date().toISOString(),
        });

        res.json({ message: 'Arquivo gerado com a chave pública fornecida.', signedFile });
    });
});

app.post('/api/decode/private/self', (req, res) => {
    const { userId, filePayload } = req.body;
    if (!userId || !filePayload)
        return res.status(400).json({ error: 'userId e filePayload são obrigatórios.' });

    if (filePayload.mode !== 'private_key')
        return res.status(400).json({ error: 'O arquivo enviado não é do tipo private_key.' });

    if (String(filePayload.signerUserId) !== String(userId))
        return res.status(403).json({ error: 'Esse arquivo não pertence à conta logada.' });

    db.get('SELECT public_key FROM users WHERE id = ?', [userId], (err, user) => {
        if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });

        const decoded = verifyPrivateKeyFile(filePayload, user.public_key);
        if (!decoded.ok) return res.status(400).json({ error: decoded.error });

        res.json(decoded.data);
    });
});

app.post('/api/decode/private/public-key', (req, res) => {
    const { filePayload, publicKey } = req.body;
    if (!filePayload || !publicKey)
        return res.status(400).json({ error: 'filePayload e publicKey são obrigatórios.' });

    if (filePayload.mode !== 'private_key')
        return res.status(400).json({ error: 'O arquivo enviado não é do tipo private_key.' });

    const decoded = verifyPrivateKeyFile(filePayload, publicKey);
    if (!decoded.ok) return res.status(400).json({ error: decoded.error });

    res.json(decoded.data);
});

app.post('/api/decode/public', (req, res) => {
    const { privateKeyPem, filePayload } = req.body;
    if (!privateKeyPem || !filePayload)
        return res.status(400).json({ error: 'privateKeyPem e filePayload são obrigatórios.' });

    if (filePayload.mode !== 'public_key')
        return res.status(400).json({ error: 'O arquivo enviado não é do tipo public_key.' });

    try {
        const message = crypto.privateDecrypt(
            {
                key: privateKeyPem,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256',
            },
            Buffer.from(filePayload.encryptedMessage, 'base64')
        ).toString('utf8');

        res.json({
            mode: filePayload.mode,
            algorithm: filePayload.algorithm,
            message,
            senderUsername: filePayload.senderUsername,
            recipientUsername: filePayload.recipientUsername,
            signedAt: filePayload.signedAt,
            status: 'DECODIFICADA',
        });
    } catch {
        res.status(400).json({ error: 'Não foi possível decodificar o arquivo. Verifique se a chave privada é a correta.' });
    }
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

// ─── HISTÓRICO DE ASSINATURAS DO USUÁRIO ─────────────────────────────────────
app.get('/api/signatures/user/:userId', (req, res) => {
    const Q = `SELECT id, original_text, text_hash, signature_hex, created_at
               FROM signatures
               WHERE user_id = ?
               ORDER BY created_at DESC`;

    db.all(Q, [req.params.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Erro ao buscar histórico.' });
        res.json(rows || []);
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
