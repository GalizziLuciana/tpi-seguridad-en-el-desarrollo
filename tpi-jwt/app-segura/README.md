# MiniBank — versión SEGURA

Mismo home banking que `../app-vulnerable`, con las defensas aplicadas. Corre en
**http://localhost:3001** para poder compararla lado a lado con la vulnerable.

```bash
npm install   # solo la primera vez
npm start     # http://localhost:3001
```

## Defensas aplicadas (a nivel de código)

1. **No implementar JWT a mano: usar una librería vetada.**
   Se usa `jsonwebtoken` en lugar de una verificación casera. (`jwt-seguro.js`)

2. **Fijar el algoritmo esperado** — la corrección central:
   ```js
   jwt.verify(token, CLAVE_PUBLICA, { algorithms: ['RS256'] });
   ```
   - Rechaza `alg:none` → neutraliza el **Ataque 1**.
   - Rechaza `HS256` → neutraliza los **Ataques 2 y 3** (ambos usaban HS256).

3. **Secreto/clave fuerte y no hardcodeado.**
   No existe ningún secreto HS256 heredado. La clave privada RSA se lee de una
   variable de entorno (`JWT_PRIVATE_KEY`) pensada para un gestor de secretos; el
   archivo local es solo para el laboratorio.

4. **Expiración corta (`exp`).** Tokens válidos 15 minutos; la librería valida `exp`.

5. **Revocación por `jti`.** Cada token lleva un id único; `POST /api/logout` lo
   agrega a una lista de invalidación. Responde a *"¿cómo se revoca una sesión
   comprometida?"*. En producción, esa lista iría en Redis o base de datos.

## Defensas a nivel de infraestructura (documentadas)

- **Rotación de claves con JWK**: el endpoint `/.well-known/jwks.json` publica la
  clave pública con su `kid`, permitiendo rotar sin romper tokens vigentes.
- **TLS obligatorio** (HTTPS) para proteger el token en tránsito.
- Si el token viajara en cookie, usar `HttpOnly` + `Secure` + `SameSite`.

## Verificación

Con la app corriendo, correr los exploits apuntando a este puerto:
```bash
cd ../exploits
BASE=http://localhost:3001 node 01-alg-none.js
BASE=http://localhost:3001 node 02-secreto-debil.js
BASE=http://localhost:3001 node 03-confusion-rs256-hs256.js
```
Los tres deben terminar en **HTTP 401** (el ataque ya no funciona).
