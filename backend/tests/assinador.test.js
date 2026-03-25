/**
 * Testes de integracao - Assinador Digital Web
 *
 * Casos cobertos:
 *   TC01 - Verificacao VALIDA   (GET /api/verify/:id - assinatura integra)
 *   TC02 - Verificacao INVALIDA (POST /api/verify - texto adulterado)
 *   TC03 - Verificacao INVALIDA (GET /api/verify/99999 - ID inexistente)
 *   TC04 - Cadastro duplicado -> HTTP 400
 *   TC05 - Login com senha errada -> HTTP 401
 *   TC06 - Geracao de arquivo com chave publica de outro usuario
 */

process.env.DB_PATH = ':memory:';

jest.resetModules();

const request = require('supertest');

let app, ready;

beforeAll(async () => {
    ({ app, ready } = require('../server'));
    await ready;
});

let userId, otherUserId, signatureId, signatureHex, privateKeyFilePayload, otherPrivateKeyFilePayload, publicKeyFilePayload, otherUserPublicKey;
const USERNAME = 'usuario_teste';
const PASSWORD = 'senha123';
const TEXTO = 'Contrato de prestacao de servicos - versao original';

describe('Setup - Cadastro e Login', () => {
    test('cadastra usuario com sucesso', async () => {
        const res = await request(app).post('/api/register').send({ username: USERNAME, password: PASSWORD });
        expect(res.statusCode).toBe(200);
        expect(res.body).toHaveProperty('userId');
        userId = res.body.userId;
    });

    test('TC04 - cadastro duplicado retorna 400', async () => {
        const res = await request(app).post('/api/register').send({ username: USERNAME, password: PASSWORD });
        expect(res.statusCode).toBe(400);
        expect(res.body).toHaveProperty('error');
    });

    test('cadastra segundo usuario para fluxo com chave publica', async () => {
        const res = await request(app).post('/api/register').send({ username: 'destinatario_teste', password: 'senha456' });
        expect(res.statusCode).toBe(200);
        expect(res.body).toHaveProperty('userId');
        otherUserId = res.body.userId;
    });

    test('baixa a chave publica do segundo usuario', async () => {
        const res = await request(app).get(`/api/users/${otherUserId}/download/public`);
        expect(res.statusCode).toBe(200);
        otherUserPublicKey = res.text;
    });

    test('login com sucesso', async () => {
        const res = await request(app).post('/api/login').send({ username: USERNAME, password: PASSWORD });
        expect(res.statusCode).toBe(200);
        expect(res.body.userId).toBe(userId);
    });

    test('TC05 - login com senha errada retorna 401', async () => {
        const res = await request(app).post('/api/login').send({ username: USERNAME, password: 'errada' });
        expect(res.statusCode).toBe(401);
    });
});

describe('Assinatura', () => {
    test('assina texto e retorna signatureId + signature + arquivo assinado', async () => {
        const res = await request(app).post('/api/sign').send({ userId, text: TEXTO });
        expect(res.statusCode).toBe(200);
        expect(res.body).toHaveProperty('signatureId');
        expect(res.body).toHaveProperty('signature');
        expect(res.body).toHaveProperty('signedFile');
        expect(res.body.signedFile).toHaveProperty('filename');
        expect(res.body.signedFile).toHaveProperty('payload');
        expect(res.body.signedFile.payload.mode).toBe('private_key');
        expect(res.body.signedFile.payload.message).toBe(TEXTO);
        expect(res.body.signedFile.payload.signature).toBe(res.body.signature);
        signatureId = res.body.signatureId;
        signatureHex = res.body.signature;
        privateKeyFilePayload = res.body.signedFile.payload;
    });

    test('TC06 - gera arquivo usando a chave publica de outro usuario', async () => {
        const res = await request(app).post('/api/sign/public').send({
            senderUserId: userId,
            recipientUserId: otherUserId,
            text: 'Mensagem reservada para o destinatario',
        });

        expect(res.statusCode).toBe(200);
        expect(res.body).toHaveProperty('signedFile');
        expect(res.body.signedFile.payload.mode).toBe('public_key');
        expect(res.body.signedFile.payload.recipientUserId).toBe(otherUserId);
        expect(res.body.signedFile.payload.senderUserId).toBe(userId);
        expect(res.body.signedFile.payload.encryptedMessage).toBeTruthy();
        publicKeyFilePayload = res.body.signedFile.payload;
    });

    test('gera arquivo private_key de outro usuario para decodificacao com chave publica', async () => {
        const res = await request(app).post('/api/sign').send({
            userId: otherUserId,
            text: 'Mensagem assinada por outra pessoa',
        });
        expect(res.statusCode).toBe(200);
        otherPrivateKeyFilePayload = res.body.signedFile.payload;
    });
});

describe('Decodificacao', () => {
    test('decodifica arquivo private_key da propria conta sem chave externa', async () => {
        const res = await request(app).post('/api/decode/private/self').send({
            userId,
            filePayload: privateKeyFilePayload,
        });
        expect(res.statusCode).toBe(200);
        expect(res.body.status).toBe('VÁLIDA');
        expect(res.body.message).toBe(TEXTO);
    });

    test('decodifica arquivo private_key de outra pessoa usando chave publica', async () => {
        const res = await request(app).post('/api/decode/private/public-key').send({
            filePayload: otherPrivateKeyFilePayload,
            publicKey: otherUserPublicKey,
        });
        expect(res.statusCode).toBe(200);
        expect(res.body.status).toBe('VÁLIDA');
        expect(res.body.message).toBe('Mensagem assinada por outra pessoa');
    });

    test('decodifica arquivo public_key com a chave privada da conta destinataria', async () => {
        const res = await request(app).post('/api/decode/public').send({
            userId: otherUserId,
            filePayload: publicKeyFilePayload,
        });
        expect(res.statusCode).toBe(200);
        expect(res.body.status).toBe('DECODIFICADA');
        expect(res.body.message).toBe('Mensagem reservada para o destinatario');
    });
});

describe('TC01 - GET /api/verify/:id -> VALIDA', () => {
    test('retorna VALIDA para assinatura integra', async () => {
        const res = await request(app).get(`/api/verify/${signatureId}`);
        expect(res.statusCode).toBe(200);
        expect(res.body.status).toBe('VÁLIDA');
        expect(res.body.signatory).toBe(USERNAME);
        expect(res.body.algorithm).toBe('RSA-SHA256');
        expect(res.body).toHaveProperty('date');
    });
});

describe('TC02 - POST /api/verify -> INVALIDA (texto adulterado)', () => {
    test('retorna INVALIDA quando texto foi modificado', async () => {
        const res = await request(app).post('/api/verify').send({
            text: TEXTO + ' - ADULTERADO',
            signature: signatureHex,
        });
        expect(res.statusCode).toBe(200);
        expect(res.body.status).toBe('INVÁLIDA');
    });
});

describe('TC03 - GET /api/verify/99999 -> INVALIDA (ID inexistente)', () => {
    test('retorna 404 e status INVALIDA', async () => {
        const res = await request(app).get('/api/verify/99999');
        expect(res.statusCode).toBe(404);
        expect(res.body.status).toBe('INVÁLIDA');
    });
});
