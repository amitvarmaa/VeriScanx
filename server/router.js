"use strict";

class Router {
  constructor() {
    this.routes = []; // { method, segments, handler }
  }
  _add(method, pattern, handler) {
    const segments = pattern.split("/").filter(Boolean);
    this.routes.push({ method, segments, handler });
  }
  get(p, h) { this._add("GET", p, h); }
  post(p, h) { this._add("POST", p, h); }
  patch(p, h) { this._add("PATCH", p, h); }
  put(p, h) { this._add("PUT", p, h); }
  delete(p, h) { this._add("DELETE", p, h); }

  match(method, pathname) {
    const parts = pathname.split("/").filter(Boolean);
    for (const route of this.routes) {
      if (route.method !== method) continue;
      if (route.segments.length !== parts.length) continue;
      const params = {};
      let ok = true;
      for (let i = 0; i < parts.length; i++) {
        const seg = route.segments[i];
        if (seg.startsWith(":")) params[seg.slice(1)] = decodeURIComponent(parts[i]);
        else if (seg !== parts[i]) { ok = false; break; }
      }
      if (ok) return { handler: route.handler, params };
    }
    return null;
  }
}

module.exports = Router;
