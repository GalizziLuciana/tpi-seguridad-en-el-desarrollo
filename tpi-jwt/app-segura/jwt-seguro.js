'use strict';

/**
 * Manejo de JWT SEGURO.
 *
 * A diferencia de la version vulnerable (que implementaba la verificacion a mano
 * y confiaba en el "alg" del token), aca:
 *
 *   1) Se usa la libreria jsonwebtoken (vetada y mantenida), NO codigo propio.
 *   2) Se FIJA el algoritmo esperado: algorithms: ['RS256'].
 *        -> rechaza alg:none            (mata el Ataque 1)
 *        -> rechaza HS256               (mata los Ataques 2 y 3, que eran HS256)
 *   3) RS256 asimetrico: se firma con la clave PRIVADA y se verifica con la
 *      PUBLICA. La clave publica NO sirve para firmar: no hay confusion posible.
 *   4) Los tokens tienen expiracion corta (exp) que la libreria valida sola.
 *   5) Soporte de revocacion por jti (lista de invalidacion en memoria).
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cfg = require('./config');

// Lista de tokens revocados (por jti). En produccion: Redis / base de datos.
const revocados = new Set();

function sign(payload) {
  return jwt.sign(payload, cfg.RSA_PRIVATE_KEY, {
    algorithm: cfg.ALG,          // firma SIEMPRE con RS256
    expiresIn: cfg.ACCESS_TTL,   // exp corto
    issuer: cfg.ISSUER,          // emisor esperado (proposito)
    audience: cfg.AUDIENCE,      // audiencia esperada (proposito)
    keyid: cfg.RSA_KID,
    jwtid: crypto.randomUUID(),  // jti unico, para poder revocar
  });
}

function verify(token) {
  // La clave: fijar algorithms + validar issuer/audience (proposito del token).
  const payload = jwt.verify(token, cfg.RSA_PUBLIC_KEY, {
    algorithms: [cfg.ALG],
    issuer: cfg.ISSUER,
    audience: cfg.AUDIENCE,
  });
  if (payload.jti && revocados.has(payload.jti)) {
    throw new Error('Token revocado');
  }
  return payload;
}

function revocar(token) {
  try {
    const decoded = jwt.decode(token);
    if (decoded && decoded.jti) revocados.add(decoded.jti);
  } catch (_) { /* ignore */ }
}

module.exports = { sign, verify, revocar };
