'use strict';

/**
 * MiniBank - servidor (version VULNERABLE).
 *
 * Es un home banking normal: el cliente ve su cuenta y puede transferir dinero.
 * NO hay ningun panel ni boton de administrador: la UI es la de un cliente comun.
 *
 * El problema: la identidad de la cuenta se toma del claim "sub" del token, y el
 * token se verifica con una funcion permisiva (jwt-vuln.js). Si el atacante forja
 * un token cambiando "sub", el servidor cree que es otra persona => puede ver y
 * operar (transferir) la cuenta de otro cliente. Esto es IDOR habilitado por el
 * forjado de JWT.
 *
 * Endpoints:
 *   POST /api/login              -> devuelve un JWT (RS256)
 *   GET  /api/cuenta             -> cuenta del "sub" del token (saldo + movimientos)
 *   POST /api/transferir         -> transfiere desde la cuenta del "sub" del token
 *   GET  /.well-known/jwks.json  -> publica la clave publica (JWK)
 *   GET  /pubkey.pem             -> clave publica en PEM (comodidad para exploits)
 */

const express = require('express');
const path = require('path');
const crypto = require('crypto');

const cfg = require('./config');
const jwt = require('./jwt-vuln');
const store = require('./db');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---- middleware de autenticacion (usa la verificacion vulnerable) ----
function auth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Falta el token (Authorization: Bearer ...)' });
  try {
    req.usuario = jwt.verify(token); // <- aqui entra la falla
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token invalido', detalle: e.message });
  }
}

// ---- login ----
app.post('/api/login', (req, res) => {
  const { usuario, clave } = req.body || {};
  const u = store.getUserByUsername(usuario);
  if (!u || !store.verifyPassword(clave, u.password)) {
    return res.status(401).json({ error: 'Usuario o clave incorrectos' });
  }
  // El token NO lleva exp en la version vulnerable (otro detalle a mejorar).
  const token = jwt.sign({ sub: u.id, usuario: u.username });
  res.json({ token });
});

// ---- cuenta: se resuelve a partir del "sub" del token (sink del IDOR) ----
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

// ---- transferencia: debita de la cuenta del "sub" del token ----
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

// ---- JWKS: publica la clave publica RSA (necesario y realista) ----
app.get('/.well-known/jwks.json', (req, res) => {
  const keyObj = crypto.createPublicKey(cfg.RSA_PUBLIC_KEY);
  const jwk = keyObj.export({ format: 'jwk' });
  res.json({ keys: [{ ...jwk, use: 'sig', alg: 'RS256', kid: cfg.RSA_KID }] });
});

// ---- clave publica en PEM (comodidad para los scripts de ataque) ----
app.get('/pubkey.pem', (req, res) => {
  res.type('text/plain').send(cfg.RSA_PUBLIC_KEY);
});

app.listen(cfg.PORT, () => {
  console.log(`\n  MiniBank (VULNERABLE) escuchando en http://localhost:${cfg.PORT}`);
  console.log('  Clientes de prueba:');
  console.log('    juan  / juan1234   (cuenta #1001, saldo $15.000)');
  console.log('    maria / maria1234  (cuenta #1002, saldo $982.000)\n');
});
