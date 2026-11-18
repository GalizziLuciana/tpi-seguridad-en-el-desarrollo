'use strict';

/**
 * Configuracion de MiniBank (version SEGURA).
 *
 * Diferencias clave respecto de la version vulnerable:
 *  - NO existe ningun secreto HS256 heredado ni hardcodeado debil.
 *  - La clave privada se lee de una variable de entorno si esta disponible
 *    (en produccion vendria de un gestor de secretos: Vault, AWS Secrets
 *    Manager, etc.), y solo cae al archivo local para facilitar el laboratorio.
 *  - Se define un tiempo de expiracion corto para los tokens.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEYS_DIR = process.env.KEYS_DIR || path.join(__dirname, 'keys');
const PRIV_PATH = path.join(KEYS_DIR, 'private.pem');
const PUB_PATH = path.join(KEYS_DIR, 'public.pem');

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
  PORT: process.env.PORT || 3001,

  // La privada idealmente viene de un gestor de secretos (env var aqui).
  RSA_PRIVATE_KEY: process.env.JWT_PRIVATE_KEY || fs.readFileSync(PRIV_PATH, 'utf8'),
  RSA_PUBLIC_KEY: fs.readFileSync(PUB_PATH, 'utf8'),

  // Unico algoritmo aceptado. Se fija explicitamente en la verificacion.
  ALG: 'RS256',

  // Expiracion corta del token de acceso.
  ACCESS_TTL: '15m',
  ACCESS_MAX_AGE_MS: 15 * 60 * 1000,

  // Claims de proposito (issuer y audience) para evitar reutilizacion entre servicios.
  ISSUER: 'minibank',
  AUDIENCE: 'minibank-clientes',

  // Nombre de la cookie de sesion (HttpOnly + SameSite=Strict).
  COOKIE_NAME: 'minibank_token',

  RSA_KID: 'minibank-rsa-2024',
};
