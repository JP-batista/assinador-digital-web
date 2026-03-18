/**
 * Testes de integração — Assinador Digital Web
 *
 * Casos cobertos:
 *   TC01 — Verificação VÁLIDA   (GET /api/verify/:id — assinatura íntegra)
 *   TC02 — Verificação INVÁLIDA (POST /api/verify   — texto adulterado)
 *   TC03 — Verificação INVÁLIDA (GET /api/verify/99999 — ID inexistente)
 *   TC04 — Cadastro duplicado → HTTP 400
 *   TC05 — Login com senha errada → HTTP 401
 */

process.env.DB_PATH = ':memory:';

jest.resetModules();

const request = require('supertest');

let app, ready;

beforeAll(async () => {
    ({ app, ready } = require('../server'));
    await ready;
});

// Estado compartilhado
let userId, signatureId, signatureHex;
const USERNAME = 'usuario_teste';
const PASSWORD = 'senha123';
const TEXTO    = 'Contrato de prestação de serviços — versão original';

// ─── Setup ────────────────────────────────────────────────────────────────────
describe('Setup — Cadastro e Login', () => {
    test('cadastra usuário com sucesso', async () => {
        const res = await request(app).post('/api/register').send({ username: USERNAME, password: PASSWORD });
        expect(res.statusCode).toBe(200);
        expect(res.body).toHaveProperty('userId');
        userId = res.body.userId;
    });

    test('TC04 — cadastro duplicado retorna 400', async () => {
        const res = await request(app).post('/api/register').send({ username: USERNAME, password: PASSWORD });
        expect(res.statusCode).toBe(400);
        expect(res.body).toHaveProperty('error');
    });

    test('login com sucesso', async () => {
        const res = await request(app).post('/api/login').send({ username: USERNAME, password: PASSWORD });
        expect(res.statusCode).toBe(200);
        expect(res.body.userId).toBe(userId);
    });

    test('TC05 — login com senha errada retorna 401', async () => {
        const res = await request(app).post('/api/login').send({ username: USERNAME, password: 'errada' });
        expect(res.statusCode).toBe(401);
    });
});

// ─── Assinatura ───────────────────────────────────────────────────────────────
describe('Assinatura', () => {
    test('assina texto e retorna signatureId + signature', async () => {
        const res = await request(app).post('/api/sign').send({ userId, text: TEXTO });
        expect(res.statusCode).toBe(200);
        expect(res.body).toHaveProperty('signatureId');
        expect(res.body).toHaveProperty('signature');
        signatureId  = res.body.signatureId;
        signatureHex = res.body.signature;
    });
});

// ─── TC01: Verificação VÁLIDA por ID ─────────────────────────────────────────
describe('TC01 — GET /api/verify/:id → VÁLIDA', () => {
    test('retorna VÁLIDA para assinatura íntegra', async () => {
        const res = await request(app).get(`/api/verify/${signatureId}`);
        expect(res.statusCode).toBe(200);
        expect(res.body.status).toBe('VÁLIDA');
        expect(res.body.signatory).toBe(USERNAME);
        expect(res.body.algorithm).toBe('RSA-SHA256');
        expect(res.body).toHaveProperty('date');
    });
});

// ─── TC02: Verificação INVÁLIDA (texto adulterado) ───────────────────────────
describe('TC02 — POST /api/verify → INVÁLIDA (texto adulterado)', () => {
    test('retorna INVÁLIDA quando texto foi modificado', async () => {
        const res = await request(app).post('/api/verify').send({
            text: TEXTO + ' — ADULTERADO',
            signature: signatureHex,
        });
        expect(res.statusCode).toBe(200);
        expect(res.body.status).toBe('INVÁLIDA');
    });
});

// ─── TC03: Verificação INVÁLIDA (ID inexistente) ─────────────────────────────
describe('TC03 — GET /api/verify/99999 → INVÁLIDA (ID inexistente)', () => {
    test('retorna 404 e status INVÁLIDA', async () => {
        const res = await request(app).get('/api/verify/99999');
        expect(res.statusCode).toBe(404);
        expect(res.body.status).toBe('INVÁLIDA');
    });
});
