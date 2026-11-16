# Propuesta de tema para TPI

**Materia:** Seguridad en el Desarrollo de Software
**Carrera:** Ingeniería en Sistemas de Información — UTN
**Opción del TPI:** 1 — Desarrollar un sitio web con una vulnerabilidad y explicar sus soluciones

---

## Tema

**Fallas de autenticación mediante JSON Web Tokens (JWT): forjado de sesión y suplantación de identidad (IDOR).**

Desarrollaremos una aplicación web — **"MiniBank"**, un home banking simplificado — que utiliza JWT para gestionar la sesión. La identidad de la cuenta se determina a partir de un dato que viaja dentro del token (el claim `sub`). La aplicación contiene fallas de autenticación deliberadas que permiten a un cliente común **falsificar su token y suplantar a otro cliente**: ver su cuenta y transferir su dinero. Luego presentaremos las soluciones aplicadas en capas (código e infraestructura) y verificaremos que los ataques dejan de funcionar.

## Vulnerabilidades a demostrar

Una sola funcionalidad (login con JWT) concentra tres fallas reales y vigentes, originadas en una verificación de token permisiva que confía en el algoritmo declarado por el propio token:

1. **Aceptación de `alg: none`** — el servidor valida el token pero admite tokens sin firma, permitiendo construir uno con la identidad de otro cliente a mano.
2. **Secreto HMAC débil** — el token se firma con HS256 y un secreto flojo, crackeable por fuerza bruta con diccionario (relación con la clase de contraseñas y hashing).
3. **Confusión de algoritmo RS256 → HS256** — el servidor no fija el algoritmo esperado; el atacante usa la clave pública (de acceso libre) como secreto HMAC para firmar tokens válidos.

En conjunto, estas fallas habilitan un **IDOR / Broken Object-Level Authorization**: al poder forjar el token, el atacante cambia el identificador de la cuenta y opera la de otra persona.

## Soluciones a explicar

- **Código:** fijar explícitamente el algoritmo en la verificación (`algorithms: ['RS256']`); secreto fuerte y no hardcodeado (variable de entorno / gestor de secretos); expiración corta (`exp`) y revocación de sesión (por `jti`); una clave por propósito.
- **Infraestructura:** rotación de claves vía JWK (`.well-known/jwks.json`), TLS obligatorio y cookies `HttpOnly` + `Secure`.

## Alcance

- Dos versiones de la app: **vulnerable** y **segura**, para comparar.
- Scripts de explotación reproducibles para cada falla.
- La app corre localmente (Node.js + Express). No se ataca ningún sistema de terceros; todo el laboratorio es propio y de uso educativo.

## Entregables

1. Código fuente de ambas versiones de la aplicación (repositorio).
2. Scripts de los tres ataques, reproducibles paso a paso.
3. **Informe técnico / tutorial** estructurado según la plantilla de reporte de vulnerabilidades vista en la unidad de Pentesting (nombre, categoría OWASP, vector CVSS, descripción, pasos para reproducir, recomendaciones).
4. Demostración en vivo durante la exposición.

## Temas de la materia que integra

Autorización y sesiones (JWT), IDOR / BOLA, JWK + OAuth2, criptografía aplicada (HMAC, simétrico vs. asimétrico), fuerza bruta y políticas de contraseñas, y plantilla de reporte de pentesting.

## Tecnologías

Node.js + Express, SQLite, librería `jsonwebtoken`; para la explotación, utilidades estándar (`jwt_tool` / `hashcat` / scripts propios). Ejecución local, opcionalmente con Docker.

---

**Integrantes del grupo:**

- Juan Martín Bisio — 401571
- Joaquín Martínez — 96110
- Kevin Lionel Matos — 400734
- Luciana Galizzi — 85465
- Joaquín Gonzales Zanotti — 89531
