// Tiny fetch wrapper + session storage. Loaded on every page.
window.VeriScanx = (function(){
  const TOKEN_KEY = 'veriscanx_token';
  const USER_KEY = 'veriscanx_user';

  function getToken(){ return localStorage.getItem(TOKEN_KEY); }
  function getUser(){ try{ return JSON.parse(localStorage.getItem(USER_KEY)||'null'); }catch{ return null; } }
  function setSession(token, user){
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  }
  function clearSession(){
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  }

  async function api(path, opts){
    opts = opts || {};
    const headers = { 'Content-Type': 'application/json' };
    if (opts.auth !== false){
      const t = getToken();
      if (t) headers['Authorization'] = 'Bearer ' + t;
    }
    const res = await fetch(path, {
      method: opts.method || 'GET',
      headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined
    });
    let data = null;
    try { data = await res.json(); } catch { /* no body */ }
    if (!res.ok){
      if (res.status === 401 && opts.auth !== false){
        clearSession();
        window.location.href = '/login.html';
      }
      throw new Error((data && data.error) || ('Request failed (' + res.status + ')'));
    }
    return data;
  }

  function requireAuth(){
    if (!getToken()){ window.location.href = '/login.html'; return false; }
    return true;
  }

  return { api, getToken, getUser, setSession, clearSession, requireAuth };
})();
