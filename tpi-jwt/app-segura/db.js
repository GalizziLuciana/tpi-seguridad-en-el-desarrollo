'use strict';

/**
 * Base de datos SQLite de MiniBank.
 * Crea el esquema y carga datos de ejemplo (clientes, cuentas y movimientos).
 *
 * Las contrasenias se guardan con scrypt + salt (visto en Criptografia aplicada),
 * NO en texto plano. El foco del TPI son los JWT, no el almacenamiento de claves,
 * pero igual se hace bien para no introducir un problema extra.
 */

const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const db = new Database(process.env.DB_PATH || path.join(__dirname, 'minibank.db'));
db.pragma('journal_mode = WAL');

function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(plain, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(plain, stored) {
  const [salt, hash] = stored.split(':');
  const calc = crypto.scryptSync(plain, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(calc, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function init() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id          INTEGER PRIMARY KEY,
      username    TEXT UNIQUE NOT NULL,
      password    TEXT NOT NULL,
      nombre      TEXT NOT NULL,
      nro_cuenta  INTEGER UNIQUE NOT NULL,   -- numero de cuenta visible
      balance     INTEGER NOT NULL           -- saldo en pesos
    );
    CREATE TABLE IF NOT EXISTS movimientos (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id   INTEGER NOT NULL,
      fecha     TEXT NOT NULL,
      detalle   TEXT NOT NULL,
      monto     INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);
}

function seed(forceReset = false) {
  if (forceReset) {
    db.exec('DELETE FROM movimientos; DELETE FROM users;');
  }
  const count = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  if (count > 0) return;

  const insUser = db.prepare(
    'INSERT INTO users (id, username, password, nombre, nro_cuenta, balance) VALUES (?, ?, ?, ?, ?, ?)'
  );
  const insMov = db.prepare(
    'INSERT INTO movimientos (user_id, fecha, detalle, monto) VALUES (?, ?, ?, ?)'
  );

  // id=2 cliente legitimo (es la cuenta del atacante en la demo)
  insUser.run(2, 'juan', hashPassword('juan1234'), 'Juan Perez', 1001, 15000);
  insMov.run(2, '2024-10-01', 'Deposito sueldo', 15000);
  insMov.run(2, '2024-10-05', 'Pago servicios', -3200);
  insMov.run(2, '2024-10-12', 'Compra supermercado', -5400);

  // id=3 otra clienta (la victima de la suplantacion)
  insUser.run(3, 'maria', hashPassword('maria1234'), 'Maria Gomez', 1002, 982000);
  insMov.run(3, '2024-10-02', 'Transferencia recibida', 982000);
  insMov.run(3, '2024-10-09', 'Pago tarjeta', -47000);

  console.log('[db] Datos de ejemplo cargados (juan #1001, maria #1002).');
}

init();
const forceSeed = require.main === module && (process.argv.includes('--seed') || process.argv.includes('--reset'));
seed(forceSeed);

// Transferencia: debita de la cuenta ORIGEN e impacta en la cuenta DESTINO.
// Devuelve el nuevo saldo de la cuenta origen. Lanza Error si algo no valida.
const transferir = db.transaction((origenUserId, nroDestino, monto) => {
  if (!Number.isInteger(monto) || monto <= 0) throw new Error('Monto invalido');

  const origen = db.prepare('SELECT * FROM users WHERE id = ?').get(origenUserId);
  if (!origen) throw new Error('Cuenta origen inexistente');

  const destino = db.prepare('SELECT * FROM users WHERE nro_cuenta = ?').get(nroDestino);
  if (!destino) throw new Error('Cuenta destino inexistente');
  if (destino.id === origen.id) throw new Error('No se puede transferir a la misma cuenta');
  if (origen.balance < monto) throw new Error('Saldo insuficiente');

  const fecha = new Date().toISOString().slice(0, 10);
  db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(monto, origen.id);
  db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(monto, destino.id);
  db.prepare('INSERT INTO movimientos (user_id, fecha, detalle, monto) VALUES (?,?,?,?)')
    .run(origen.id, fecha, `Transferencia a cuenta ${nroDestino}`, -monto);
  db.prepare('INSERT INTO movimientos (user_id, fecha, detalle, monto) VALUES (?,?,?,?)')
    .run(destino.id, fecha, `Transferencia de ${origen.nombre}`, monto);

  return db.prepare('SELECT balance FROM users WHERE id = ?').get(origen.id).balance;
});

module.exports = {
  db,
  hashPassword,
  verifyPassword,
  transferir,
  getUserByUsername: (u) => db.prepare('SELECT * FROM users WHERE username = ?').get(u),
  getUserById: (id) => db.prepare('SELECT * FROM users WHERE id = ?').get(id),
  getMovimientos: (id) =>
    db.prepare('SELECT fecha, detalle, monto FROM movimientos WHERE user_id = ? ORDER BY id').all(id),
};
