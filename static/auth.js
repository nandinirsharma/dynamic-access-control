// static/auth.js
// Client-side helpers used by login.html, register.html and dashboard

// Save token helper
function saveToken(token) {
  try { localStorage.setItem('access_token', token); } catch(e) {}
}

// Remove token helper
function clearToken() {
  try { localStorage.removeItem('access_token'); } catch(e) {}
}

// Login: username, password, optional device_type (string), optional ip (string)
window.authLogin = async function(username, password, device_type, ip) {
  try {
    const body = { username, password };
    if (device_type) body.device_type = device_type;
    if (ip) body.ip = ip;
    const resp = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await resp.json().catch(()=>({}));
    if (resp.status === 200 && data.access_token) {
      saveToken(data.access_token);
      return { ok: true, device_matched: !!data.device_matched, raw: data };
    }
    return { ok: false, status: resp.status, raw: data };
  } catch (e) {
    console.error('Login network error', e);
    return { ok: false, error: e.message };
  }
};

// Register: username, password, optional device_type
window.authRegister = async function(username, password, device_type) {
  try {
    const body = { username, password };
    if (device_type) body.device_type = device_type;
    const resp = await fetch('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await resp.json().catch(()=>({}));
    return { status: resp.status, raw: data };
  } catch (e) {
    console.error('Register network error', e);
    return { status: 0, raw: { error: e.message } };
  }
};

// Logout: calls /logout with current token; clears token on client in all cases
window.authLogout = async function() {
  try {
    const token = localStorage.getItem('access_token') || '';
    if (!token) {
      clearToken();
      return { ok: true, message: 'no-token' };
    }
    const resp = await fetch('/logout', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token }
    });
    let data = {};
    try { data = await resp.json(); } catch(e){}
    clearToken();
    if (resp.status === 200) {
      return { ok: true, raw: data };
    } else {
      return { ok: false, status: resp.status, raw: data };
    }
  } catch (e) {
    console.error('logout failed', e);
    clearToken();
    return { ok: false, error: e.message };
  }
};
