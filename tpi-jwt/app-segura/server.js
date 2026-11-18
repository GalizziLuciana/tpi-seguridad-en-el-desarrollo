'use strict';

/**
 * MiniBank - servidor (version SEGURA).
 *
 * Mismos endpoints y misma funcionalidad que la version vulnerable, pero con la
 * verificacion de JWT corregida (ver jwt-seguro.js). Corre en el puerto 3001
 * para poder compararla lado a lado con la vulnerable (3000).
 *
 * Nota de defensa en profundidad: ademas de arreglar el JWT, se sigue validando
 * del lado del servidor (el sub del token identifica la cuenta). El arreglo del
 * JWT evita que ese sub pueda ser falsificado.
 */

const express = require('express');
const path = require('path');
const crypto = require('crypto');

const cfg = require('./config');
const jwt = require('./jwt-seguro');
const store = require('./db');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Extrae una cookie por nombre sin dependencias externas.
function getCookie(req, name) {
  const raw = req.headers['cookie'];
  if (!raw) return null;
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

function auth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const bearer = header.startsWith('Bearer ') ? header.slice(7) : null;
  const token = bearer || getCookie(req, cfg.COOKIE_NAME);
  if (!token) return res.status(401).json({ error: 'Falta el token (Authorization: Bearer o Cookie HttpOnly)' });
  try {
    req.token = token;
    req.usuario = jwt.verify(token); // verificacion segura: algorithms + iss/aud + exp + revocacion
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token invalido', detalle: e.message });
  }
}

app.post('/api/login', (req, res) => {
  const { usuario, clave } = req.body || {};
  const u = store.getUserByUsername(usuario);
  if (!u || !store.verifyPassword(clave, u.password)) {
    return res.status(401).json({ error: 'Usuario o clave incorrectos' });
  }
  const token = jwt.sign({ sub: u.id, usuario: u.username });
  // Envia el token en cookie HttpOnly + SameSite=Strict (+ Secure en produccion/TLS)
  res.cookie(cfg.COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge: cfg.ACCESS_MAX_AGE_MS,
  });
  res.json({ token });
});

app.post('/api/logout', auth, (req, res) => {
  jwt.revocar(req.token); // invalida el jti aunque no haya expirado
  res.clearCookie(cfg.COOKIE_NAME, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
  });
  res.json({ ok: true, mensaje: 'Sesion revocada' });
});

app.get('/api/cuenta', auth, (req, res) => {
  const u = store.getUserById(req.usuario.sub);
  if (!u) return res.status(404).json({ error: 'Cuenta no encontrada' });
  res.json({
    titular: u.nombre,
    nro_cuenta: u.nro_cuenta,
    balance: u.balance,
    movimientos: store.getMovimientos(u.id),
  });
});

app.post('/api/transferir', auth, (req, res) => {
  const { cuenta_destino, monto } = req.body || {};
  try {
    const nuevoSaldo = store.transferir(
      req.usuario.sub,
      parseInt(cuenta_destino, 10),
      parseInt(monto, 10)
    );
    res.json({ ok: true, mensaje: 'Transferencia realizada', nuevo_saldo: nuevoSaldo });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// JWKS: se sigue publicando la clave publica (es correcto y util para rotacion).
app.get('/.well-known/jwks.json', (req, res) => {
  const keyObj = crypto.createPublicKey(cfg.RSA_PUBLIC_KEY);
  const jwk = keyObj.export({ format: 'jwk' });
  res.json({ keys: [{ ...jwk, use: 'sig', alg: cfg.ALG, kid: cfg.RSA_KID }] });
});

app.get('/pubkey.pem', (req, res) => {
  res.type('text/plain').send(cfg.RSA_PUBLIC_KEY);
});

app.listen(cfg.PORT, () => {
  console.log(`\n  MiniBank (SEGURA) escuchando en http://localhost:${cfg.PORT}`);
  console.log('  Clientes de prueba:');
  console.log('    juan  / juan1234   (cuenta #1001)');
  console.log('    maria / maria1234  (cuenta #1002)\n');
});
