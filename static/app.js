const $ = (id) => document.getElementById(id);
const wallet = { access: '', refresh: '', previous: '', claims: null, ttl: 20, revoked: false };
let busy = false;
let sequence = 0;
const pretty = (value) => JSON.stringify(value, null, 2);
function decode(part) {
  const base64 = part.replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')), c => c.charCodeAt(0))));
}
function render() {
  document.querySelectorAll('button').forEach(button => {
    const need = button.dataset.needs;
    button.disabled = busy || Boolean(need && !wallet[need]);
  });
  $('session').textContent = wallet.claims ? `${wallet.claims.username.toUpperCase()} · ${wallet.revoked ? 'LOGGED OUT' : wallet.claims.role.toUpperCase()}` : 'NO TOKENS';
  $('refresh-token').textContent = wallet.refresh || 'Sign in to see your refresh token';
  $('refresh-state').textContent = wallet.refresh ? (wallet.revoked ? 'Revoked on server' : 'Issued · 7-day lifetime') : 'Not issued';
  $('old-refresh').textContent = wallet.previous || 'Refresh once to compare the old and new tokens.';
  $('old-state').textContent = wallet.previous ? '· consumed' : '';
  if (wallet.access) {
    $('access-token').replaceChildren();
    wallet.access.split('.').forEach((part, i) => {
      const span = document.createElement('span');
      span.className = ['header-color', 'payload-color', 'signature-color'][i];
      span.textContent = (i ? '.' : '') + part;
      $('access-token').append(span);
    });
    $('header').textContent = pretty(decode(wallet.access.split('.')[0]));
    $('payload').textContent = pretty(wallet.claims);
  }
  tick();
}
function tick() {
  if (!wallet.claims) return;
  const left = Math.max(0, wallet.claims.exp - Date.now() / 1000);
  $('expiry').textContent = left > 0 ? `${Math.ceil(left)}s remaining` : 'Expired · try GET /me';
  $('lifetime').style.width = `${Math.min(100, left / wallet.ttl * 100)}%`;
}
function mark(step) {
  document.querySelectorAll('.flow span').forEach(el => el.classList.toggle('active', el.id === `flow-${step}`));
}
function adopt(data) {
  wallet.access = data.access_token;
  wallet.refresh = data.refresh_token;
  wallet.ttl = data.expires_in;
  wallet.claims = decode(wallet.access.split('.')[1]);
  wallet.revoked = false;
}
function explain(path, status, data) {
  if (status === 401) return `Rejected: ${data.error}. ${path === '/refresh' ? 'Refresh tokens must still exist in the server’s store and must not be expired.' : 'The request did not establish a valid identity.'}`;
  if (status === 403) return 'Identity verified, permission denied. The token is valid, but this user is not an admin.';
  if (status >= 400) return `Request rejected: ${data?.error || status}`;
  if (path === '/login') return 'Password checked → server signed an access JWT → server stored a random refresh token → browser received both.';
  if (path === '/refresh') return 'Server consumed the refresh token → issued a new access JWT and refresh token. The old refresh token can no longer be used.';
  if (path === '/logout') return 'Server removed the refresh token. The access JWT remains valid until expiry. Try Refresh and GET /me to compare.';
  if (path === '/company/employees') return 'Signature and expiry verified → company_id from the verified token selected which employees you can see.';
  return 'Bearer token received → signature and expiry verified → claims used to authorize the request → response returned.';
}
function addTrace(method, path, headers, body, status, data, elapsed, explanation) {
  $('trace').querySelector('.empty')?.remove();
  $('trace').querySelectorAll('details').forEach(el => { el.open = false; });
  const entry = document.createElement('details');
  entry.className = 'exchange'; entry.open = true;
  const summary = document.createElement('summary');
  const badge = document.createElement('span'); badge.className = `status${status >= 400 || status === 'NETWORK' ? ' error' : ''}`; badge.textContent = status;
  const title = document.createElement('code'); title.textContent = `${method} ${path}`;
  const timing = document.createElement('span'); timing.className = 'timing'; timing.textContent = `#${++sequence} · ${elapsed} ms · ${new Date().toLocaleTimeString()}`;
  summary.append(badge, title, timing);
  const note = document.createElement('p'); note.textContent = explanation;
  const wire = document.createElement('div'); wire.className = 'wire';
  for (const [label, content] of [['REQUEST', `${method} ${path}\n${Object.entries(headers).map(([k,v]) => `${k}: ${v}`).join('\n')}${body ? '\n\n' + pretty(body) : ''}`], ['RESPONSE', `${status}\n\n${data === null ? '(empty body)' : pretty(data)}`]]) {
    const col = document.createElement('div'); const heading = document.createElement('h4'); heading.textContent = label;
    const pre = document.createElement('pre'); pre.className = 'raw'; pre.textContent = content;
    col.append(heading, pre); wire.append(col);
  }
  entry.append(summary, note, wire); $('trace').prepend(entry);
}
async function request(method, path, { body, token } = {}) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;
  const start = performance.now();
  const response = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(10000) });
  const data = response.status === 204 ? null : await response.json();
  const explanation = explain(path, response.status, data);
  addTrace(method, path, headers, body, response.status, data, Math.round(performance.now() - start), explanation);
  $('notice').textContent = explanation;
  return { ok: response.ok, data };
}
async function run(action) {
  if (busy) return;
  busy = true; render();
  try { await action(); }
  catch (error) {
    $('notice').textContent = `Could not complete the request: ${error.message}. Check that the Python server is running, then retry.`;
  } finally { busy = false; render(); }
}
$('user').addEventListener('change', () => { $('password').value = `${$('user').value}-pass`; });
$('login-form').addEventListener('submit', event => {
  event.preventDefault();
  run(async () => {
    mark('login');
    const result = await request('POST', '/login', { body: { username: $('user').value, password: $('password').value, access_ttl: Number($('ttl').value) } });
    if (result.ok) { adopt(result.data); wallet.previous = ''; }
    else if (wallet.access) $('notice').textContent += ' The previously issued tokens remain in the wallet.';
  });
});
document.querySelectorAll('[data-action]').forEach(button => button.addEventListener('click', () => run(async () => {
  const action = button.dataset.action;
  if (['refresh', 'reuse'].includes(action)) {
    mark('refresh');
    const old = wallet.refresh;
    const result = await request('POST', '/refresh', { body: { refresh_token: action === 'reuse' ? wallet.previous : old } });
    if (result.ok) { adopt(result.data); wallet.previous = old; }
  } else if (action === 'logout') {
    mark('logout');
    const result = await request('POST', '/logout', { body: { refresh_token: wallet.refresh } });
    if (result.ok) wallet.revoked = true;
  } else {
    mark('access');
    let token = action === 'missing' ? '' : wallet.access;
    if (action === 'tamper') {
      const parts = token.split('.');
      const bytes = new TextEncoder().encode(JSON.stringify({ ...wallet.claims, role: 'admin' }));
      parts[1] = btoa(String.fromCharCode(...bytes)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      token = parts.join('.');
    }
    const path = { admin: '/admin', tamper: '/admin', company: '/company/employees' }[action] || '/me';
    await request('GET', path, { token });
  }
})));
$('clear').addEventListener('click', () => { $('trace').replaceChildren(); sequence = 0; });
setInterval(tick, 250);
render();
