'use strict';

/**
 * Implementacion MINIMA y VULNERABLE de JWT.
 *
 * Se implementa a mano (en vez de usar la libreria tal cual) para que la falla
 * quede VISIBLE en el codigo: es el material del informe tecnico.
 *
 * Los tokens son JWT estandar e interoperables (sirven en jwt.io, jwt_tool, etc.).
 *
 * ------------------------------------------------------------------------------
 * RAIZ DE LAS 3 VULNERABILIDADES  ->  funcion verify()
 *   El servidor CONFIA en el campo "alg" del header del token y prueba con
 *   cualquiera de las claves que conoce. Nunca fija el algoritmo esperado.
 *
 *   A) alg="none"  -> acepta el token SIN verificar firma.
 *   B) alg="HS256" -> verifica HMAC con el secreto heredado DEBIL ("secret").
 *   C) alg="HS256" -> si B falla, ademas prueba usar la CLAVE PUBLICA RSA como
 *                     secreto HMAC  => confusion de algoritmo RS256 -> HS256.
 * ------------------------------------------------------------------------------
 */

const crypto = require('crypto');
const cfg = require('./config');

// ---- helpers base64url ----
const b64url = (buf) =>
  Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlJson = (obj) => b64url(JSON.stringify(obj));
const fromB64url = (str) =>
  Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

// Comparacion de firmas (como la harian muchos devs).
function sigEquals(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// ----------------------------------------------------------------------------
// FIRMA: el servidor emite tokens RS256 (el esquema "actual" post-migracion).
// ----------------------------------------------------------------------------
function sign(payload) {
  const header = { alg: 'RS256', typ: 'JWT', kid: cfg.RSA_KID };
  const body = { ...payload, iat: Math.floor(Date.now() / 1000) };
  const data = `${b64urlJson(header)}.${b64urlJson(body)}`;
  const signature = crypto.sign('RSA-SHA256', Buffer.from(data), cfg.RSA_PRIVATE_KEY);
  return `${data}.${b64url(signature)}`;
}

// Emision legacy (HS256 con el secreto debil heredado), util para demostrar en vivo
// como se generaban los tokens antes de la migracion a RS256.
function signLegacy(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const body = { ...payload, iat: Math.floor(Date.now() / 1000) };
  const data = `${b64urlJson(header)}.${b64urlJson(body)}`;
  const signature = crypto.createHmac('sha256', cfg.LEGACY_HS_SECRET).update(data).digest();
  return `${data}.${b64url(signature)}`;
}

// ----------------------------------------------------------------------------
// VERIFICACION VULNERABLE
// ----------------------------------------------------------------------------
function verify(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Formato de token invalido');

  const [h, p, s] = parts;
  const header = JSON.parse(fromB64url(h).toString('utf8'));
  const payload = JSON.parse(fromB64url(p).toString('utf8'));
  const signingInput = `${h}.${p}`;

  // ---- expiracion (si existe) ----
  if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) {
    throw new Error('Token expirado');
  }

  // >>> AQUI ESTA LA FALLA: confiar en header.alg <<<
  const alg = header.alg;

  // (A) VULNERABILIDAD: algoritmo "none" aceptado sin firma (cualquier capitalizacion).
  if (typeof alg === 'string' && alg.toLowerCase() === 'none') {
    return payload;
  }

  // (B y C) VULNERABILIDAD: HS256 verificado contra CUALQUIER clave conocida.
  if (alg === 'HS256') {
    const expected = s; // firma que trae el token (base64url)

    // (B) secreto heredado debil
    const hmacLegacy = b64url(
      crypto.createHmac('sha256', cfg.LEGACY_HS_SECRET).update(signingInput).digest()
    );
    if (sigEquals(expected, hmacLegacy)) return payload;

    // (C) confusion de algoritmo: se usa la clave PUBLICA RSA como secreto HMAC
    const hmacPub = b64url(
      crypto.createHmac('sha256', cfg.RSA_PUBLIC_KEY).update(signingInput).digest()
    );
    if (sigEquals(expected, hmacPub)) return payload;

    throw new Error('Firma HS256 invalida');
  }

  // Camino "correcto": RS256 con la clave publica.
  if (alg === 'RS256') {
    const ok = crypto.verify(
      'RSA-SHA256',
      Buffer.from(signingInput),
      cfg.RSA_PUBLIC_KEY,
      fromB64url(s)
    );
    if (!ok) throw new Error('Firma RS256 invalida');
    return payload;
  }

  throw new Error(`Algoritmo no soportado: ${alg}`);
}

module.exports = { sign, signLegacy, verify, b64url, b64urlJson };
