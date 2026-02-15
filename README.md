# JWKS Server (Go)

A simple JWKS + JWT auth server that generates RSA key pairs (active + expired) and issues RS256 JWTs with the correct `kid`.

## Requirements Covered

- RSA keypair generation with `kid` and expiry timestamp
- JWKS endpoint serves **only unexpired** public keys
- `/auth` returns a **valid RS256 JWT** on **POST**
- `/auth?expired=1` returns an **expired JWT** signed with the expired key
- Proper HTTP methods/status codes (e.g., `GET /auth` → 405)
- Tests included with **> 80% coverage**
- Project is organized + documented

---

## Endpoints

### `GET /.well-known/jwks.json`
Returns a JWKS containing **only the active (unexpired) RSA public key**.

### `POST /auth`
Returns a **valid RS256 JWT** signed with the active private key.  
JWT header includes `kid` that matches the key in the JWKS.

### `POST /auth?expired=1`
Returns an **expired JWT** signed with the expired private key.  
JWT is correctly signed, but the `exp` claim is in the past.

### `GET /auth`
Returns **405 Method Not Allowed**

---

## Run locally

```bash
go run ./cmd/server
