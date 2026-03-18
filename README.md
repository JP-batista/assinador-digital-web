# Assinador Digital Web

Aplicação web para assinatura digital de documentos com criptografia assimétrica RSA-2048 e hash SHA-256.

**Dupla:** _[insira os nomes]_

---

## Tecnologias

| Camada    | Tecnologia                         |
|-----------|------------------------------------|
| Backend   | Node.js · Express 5 · Crypto nativo |
| Banco     | SQLite (arquivo local)              |
| Frontend  | HTML5 · JavaScript Vanilla          |
| Testes    | Jest · Supertest                    |

---

## Como rodar

### Pré-requisitos
- Node.js 18+

### Passos

```bash
cd backend
npm install
npm start
```

Acesse: `http://localhost:3000`

---

## Fluxos

### 1. Cadastro
O usuário cria uma conta. O servidor gera automaticamente um par de chaves RSA-2048 e persiste no banco.

### 2. Assinatura (área autenticada)
O usuário digita um texto. O servidor:
1. Calcula o SHA-256 do texto
2. Assina com a chave privada do usuário
3. Persiste a assinatura e retorna o **ID** e o hash

### 3. Verificação (pública)
Qualquer pessoa pode verificar uma assinatura de duas formas:
- **Por ID**: fornece o ID retornado na assinatura
- **Por texto + assinatura**: cola o texto original e a string hexadecimal da assinatura

O sistema retorna `VÁLIDA` ou `INVÁLIDA`, exibindo signatário, algoritmo e data/hora. Cada verificação é registrada na tabela `logs`.

---

## Endpoints

### `POST /api/register`
Cadastra novo usuário e gera par de chaves RSA.

**Body:**
```json
{ "username": "joao", "password": "senha123" }
```

**Resposta (200):**
```json
{ "message": "Usuário cadastrado com sucesso!", "userId": 1 }
```

---

### `POST /api/login`
Autentica o usuário.

**Body:**
```json
{ "username": "joao", "password": "senha123" }
```

**Resposta (200):**
```json
{ "message": "Login realizado com sucesso.", "userId": 1, "username": "joao" }
```

**Resposta (401):**
```json
{ "error": "Credenciais inválidas." }
```

---

### `POST /api/sign`
Assina um texto com a chave privada do usuário.

**Body:**
```json
{ "userId": 1, "text": "Contrato de prestação de serviços — v1" }
```

**Resposta (200):**
```json
{
  "message": "Documento assinado com sucesso!",
  "signatureId": 3,
  "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "signature": "4a9f1c...hex longo..."
}
```

---

### `GET /api/verify/:id`
Verifica assinatura pelo ID.

**Exemplo:** `GET /api/verify/3`

**Resposta — válida (200):**
```json
{
  "status": "VÁLIDA",
  "signatureId": 3,
  "signatory": "joao",
  "algorithm": "RSA-SHA256",
  "date": "2025-06-10T14:32:00.000Z",
  "text": "Contrato de prestação de serviços — v1"
}
```

**Resposta — não encontrado (404):**
```json
{ "status": "INVÁLIDA", "reason": "ID de assinatura não encontrado." }
```

---

### `POST /api/verify`
Verifica assinatura por texto + hex (cola manual).

**Body:**
```json
{
  "text": "Contrato de prestação de serviços — v1",
  "signature": "4a9f1c...hex..."
}
```

**Resposta — inválida (texto adulterado):**
```json
{ "status": "INVÁLIDA" }
```

---

## Schema do Banco

O arquivo `backend/migrate.sql` contém o dump completo do schema. As tabelas são criadas automaticamente ao iniciar o servidor.

```
users       — id, username, password, public_key, private_key, created_at
signatures  — id, user_id, original_text, text_hash, signature_hex, created_at
logs        — id, signature_id, is_valid, checked_at
```

---

## Testes

```bash
cd backend
npm test
```

**Casos cobertos:**

| Caso | Descrição | Esperado |
|------|-----------|----------|
| TC01 | Verificação por ID com assinatura íntegra | `VÁLIDA` |
| TC02 | Verificação com texto adulterado | `INVÁLIDA` |
| TC03 | Verificação com ID inexistente | `INVÁLIDA` · HTTP 404 |
| TC04 | Cadastro de usuário duplicado | HTTP 400 |
| TC05 | Login com senha errada | HTTP 401 |
