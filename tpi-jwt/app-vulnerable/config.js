'use strict';

/**
 * Configuracion de MiniBank (version VULNERABLE).
 *
 * Narrativa: MiniBank nacio usando JWT firmados con HS256 y un secreto simple.
 * Mas tarde "migro" a RS256 (clave publica/privada). Durante la migracion, para
 * no romper sesiones viejas, dejaron una verificacion PERMISIVA que acepta
 * cualquier algoritmo que diga el token y prueba con todas las claves conocidas.
 * Esa unica decision es la raiz de las tres vulnerabilidades del TPI.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEYS_DIR = path.join(__dirname, 'keys');
const PRIV_PATH = path.join(KEYS_DIR, 'private.pem');
const PUB_PATH = path.join(KEYS_DIR, 'public.pem');

// Genera el par de claves RSA la primera vez (para que no haya pasos manuales).
function ensureRsaKeys() {
  if (!fs.existsSync(KEYS_DIR)) fs.mkdirSync(KEYS_DIR, { recursive: true });
  if (!fs.existsSync(PRIV_PATH) || !fs.existsSync(PUB_PATH)) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    fs.writeFileSync(PRIV_PATH, privateKey);
    fs.writeFileSync(PUB_PATH, publicKey);
    console.log('[config] Par de claves RSA generado en keys/');
  }
}
ensureRsaKeys();

module.exports = {
  PORT: process.env.PORT || 3000,

  // Clave privada RSA: firma los tokens "actuales" (RS256).
  RSA_PRIVATE_KEY: fs.readFileSync(PRIV_PATH, 'utf8'),
  // Clave publica RSA: se publica (JWKS) y sirve para verificar RS256.
  RSA_PUBLIC_KEY: fs.readFileSync(PUB_PATH, 'utf8'),

  // VULNERABILIDAD B: secreto HS256 "heredado", debil y hardcodeado.
  // Esta en todos los diccionarios comunes -> crackeable en segundos.
  LEGACY_HS_SECRET: 'secret',

  // Identificador de la clave (para el JWKS).
  RSA_KID: 'minibank-rsa-2024',
};
