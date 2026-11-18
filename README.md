# TPI — Fallas de autenticación con JWT en "MiniBank"

Trabajo Práctico Integrador de **Seguridad en el Desarrollo de Software** (UTN).
Opción 1: desarrollar un sitio web con una vulnerabilidad y explicar sus soluciones.

**Integrantes:** Juan Martín Bisio (401571), Joaquín Martínez (96110),
Kevin Lionel Matos (400734), Luciana Galizzi (85465), Joaquín Gonzales Zanotti (89531).

## Idea

**MiniBank** es un home banking simplificado. La vista del cliente le permite ver
su cuenta y transferir dinero. La identidad de la cuenta se toma del claim `sub`
del JWT de sesión. Si un atacante puede **forjar** ese token, puede cambiar el
`sub` y **operar la cuenta de otro cliente** (ver saldo y transferir su dinero):
es un IDOR habilitado por fallas en la verificación del JWT.

## Estructura

| Carpeta | Qué es |
|---------|--------|
| `tpi-jwt/app-vulnerable/` | MiniBank con 3 fallas de verificación de JWT. Puerto **3000**. |
| `tpi-jwt/app-segura/`     | Mismo MiniBank con las defensas aplicadas. Puerto **3001**. |
| `tpi-jwt/exploits/`       | 3 scripts que forjan tokens y suplantan a otra clienta. |
| `tpi-jwt/docs/`           | Propuesta para Moodle (md + pdf) e informe técnico. |

## Las 3 fallas (misma raíz)

El servidor vulnerable **confía en el campo `alg`** del token y no fija el
algoritmo esperado. De ahí:

1. **`alg:none`** — acepta tokens sin firma.
2. **Secreto HMAC débil** — acepta HS256 con un secreto adivinable (`secret`).
3. **Confusión RS256→HS256** — acepta HS256 firmado con la clave pública.

## Cómo correrlo

```bash
# 1) App vulnerable (puerto 3000)
cd tpi-jwt/app-vulnerable && npm install && npm start

# 2) Exploits (en otra terminal)
cd tpi-jwt/exploits
node 01-alg-none.js
node 02-secreto-debil.js
node 03-confusion-rs256-hs256.js

# 3) App segura (puerto 3001) y re-ejecución de los exploits (deben fallar con 401)
cd tpi-jwt/app-segura && npm install && npm start
cd ../exploits
node 01-alg-none.js --segura
node 02-secreto-debil.js --segura
node 03-confusion-rs256-hs256.js --segura

# Opcional: correr todo junto (con ambas apps levantadas) o usar Docker
node verificar-todo.js
cd .. && docker compose up --build
```

Clientes de prueba: `juan / juan1234` (cuenta #1001) y `maria / maria1234`
(cuenta #1002).

## La corrección central

```js
// Vulnerable: confía en el alg del token (verificación casera).
// Segura:
jwt.verify(token, CLAVE_PUBLICA, { algorithms: ['RS256'] });
```

Fijar el algoritmo rompe los ataques 1 y 3 de inmediato; sumado a eliminar el
secreto HS256 débil, también el 2. Detalle completo en `app-segura/README.md`.

> Laboratorio con fines educativos. Todo corre localmente; no se ataca ningún
> sistema de terceros.
