'use strict';

// En la version SEGURA, el servidor emite el JWT en una cookie HttpOnly + SameSite=Strict.
// El navegador la envia automaticamente en cada request same-origin y el token NO se guarda
// en localStorage (protegiendolo frente a robo por XSS).
const $ = (id) => document.getElementById(id);
const fmt = (n) => '$' + n.toLocaleString('es-AR');

async function api(path, opts = {}) {
  const headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
  const res = await fetch(path, Object.assign({ credentials: 'same-origin' }, opts, { headers }));
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
  if (!c.ok) { logout(false); return; }
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

async function logout(revocarEnServidor = true) {
  if (revocarEnServidor) {
    await api('/api/logout', { method: 'POST' }).catch(() => {});
  }
  localStorage.removeItem('minibank_token');
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
  cargarCuenta();
});

$('logoutBtn').addEventListener('click', () => logout(true));

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

// al cargar: intentar recuperar sesion activa mediante la cookie HttpOnly
cargarCuenta();
