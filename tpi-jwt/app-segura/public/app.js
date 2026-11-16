'use strict';

// Para la demo guardamos el token en localStorage y lo enviamos en el header
// Authorization. Esto facilita ver y manipular el token (foco del TPI).
const $ = (id) => document.getElementById(id);
const fmt = (n) => '$' + n.toLocaleString('es-AR');

function getToken() { return localStorage.getItem('minibank_token'); }
function setToken(t) { localStorage.setItem('minibank_token', t); }
function clearToken() { localStorage.removeItem('minibank_token'); }

async function api(path, opts = {}) {
  const headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
  const token = getToken();
  if (token) headers['Authorization'] = 'Bearer ' + token;
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

function show(view) {
  $('loginView').classList.toggle('hidden', view !== 'login');
  $('cuentaView').classList.toggle('hidden', view !== 'cuenta');
  $('userbox').classList.toggle('hidden', view !== 'cuenta');
}

async function cargarCuenta() {
  const c = await api('/api/cuenta');
  if (!c.ok) { logout(); return; }
  $('userLabel').textContent = `${c.data.titular} — cuenta ${c.data.nro_cuenta}`;
  $('titular').textContent = c.data.titular;
  $('nroCuenta').textContent = c.data.nro_cuenta;
  $('balance').textContent = fmt(c.data.balance);
  $('movBody').innerHTML = c.data.movimientos
    .map((m) => `<tr><td>${m.fecha}</td><td>${m.detalle}</td><td>${fmt(m.monto)}</td></tr>`)
    .join('');
  $('transferMsg').textContent = '';
  show('cuenta');
}

function logout() {
  clearToken();
  show('login');
}

$('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('loginError').textContent = '';
  const r = await api('/api/login', {
    method: 'POST',
    body: JSON.stringify({ usuario: $('usuario').value, clave: $('clave').value }),
  });
  if (!r.ok) { $('loginError').textContent = r.data.error || 'Error de login'; return; }
  setToken(r.data.token);
  cargarCuenta();
});

$('logoutBtn').addEventListener('click', logout);

$('transferForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const msg = $('transferMsg');
  const r = await api('/api/transferir', {
    method: 'POST',
    body: JSON.stringify({ cuenta_destino: $('destino').value, monto: $('monto').value }),
  });
  if (r.ok) {
    msg.className = 'msg ok';
    msg.textContent = `${r.data.mensaje}. Nuevo saldo: ${fmt(r.data.nuevo_saldo)}`;
    cargarCuenta().then(() => { $('transferMsg').className = 'msg ok'; $('transferMsg').textContent = msg.textContent; });
  } else {
    msg.className = 'msg error';
    msg.textContent = r.data.error || 'No se pudo transferir';
  }
});

// al cargar: si ya hay token, intentar entrar
if (getToken()) cargarCuenta(); else show('login');
