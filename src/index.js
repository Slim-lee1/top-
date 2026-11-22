const enc = new TextEncoder();

const hex = (buf) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => new Uint8Array(h.match(/.{2}/g).map((b) => parseInt(b, 16)));
const randomHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));

async function sha256(text) {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}

async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: fromHex(saltHex), iterations: 100000 },
    key,
    256
  );
  return hex(bits);
}

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });

function sessionCookie(request, token, maxAge) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`;
}

function getToken(request) {
  const m = (request.headers.get("Cookie") || "").match(/(?:^|;\s*)session=([a-f0-9]+)/);
  return m ? m[1] : null;
}

async function createSession(env, email) {
  const token = randomHex(32);
  await env.DB.prepare(
    "INSERT INTO sessions (token, email, expires_at) VALUES (?, ?, datetime('now', '+7 days'))"
  ).bind(await sha256(token), email).run();
  return token;
}

async function getUser(request, env) {
  const token = getToken(request);
  if (!token) return null;
  return await env.DB.prepare(
    `SELECT u.id, u.email, u.name FROM sessions s
     JOIN users u ON u.email = s.email
     WHERE s.token = ? AND s.expires_at > datetime('now')`
  ).bind(await sha256(token)).first();
}

async function signup(request, env) {
  const { name, email, password } = await request.json().catch(() => ({}));
  const e = (email || "").trim().toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(e) || !password || password.length < 8)
    return json({ error: "Valid email and a password of 8+ characters required" }, 400);

  const exists = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(e).first();
  if (exists) return json({ error: "Account already exists" }, 409);

  const salt = randomHex(16);
  const hash = await hashPassword(password, salt);
  await env.DB.prepare(
    "INSERT INTO users (email, name, password_hash, password_salt) VALUES (?, ?, ?, ?)"
  ).bind(e, (name || "").trim(), hash, salt).run();

  const token = await createSession(env, e);
  return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(request, token, 604800) });
}

async function login(request, env) {
  const { email, password } = await request.json().catch(() => ({}));
  const e = (email || "").trim().toLowerCase();
  const ip = request.headers.get("CF-Connecting-IP") || "";

  const { n } = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM login_attempts WHERE email = ? AND success = 0 AND created_at > datetime('now','-15 minutes')"
  ).bind(e).first();
  if (n >= 5) return json({ error: "Too many attempts. Try again in 15 minutes." }, 429);

  const user = await env.DB.prepare(
    "SELECT password_hash, password_salt FROM users WHERE email = ?"
  ).bind(e).first();

  let ok = false;
  if (user && user.password_hash) {
    ok = (await hashPassword(password || "", user.password_salt)) === user.password_hash;
  }
  await env.DB.prepare(
    "INSERT INTO login_attempts (email, ip, success) VALUES (?, ?, ?)"
  ).bind(e, ip, ok ? 1 : 0).run();

  if (!ok) return json({ error: "Invalid email or password" }, 401);

  const token = await createSession(env, e);
  return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(request, token, 604800) });
}

async function logout(request, env) {
  const token = getToken(request);
  if (token) {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(await sha256(token)).run();
  }
  return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(request, "", 0) });
}

async function me(request, env) {
  const user = await getUser(request, env);
  if (!user) return json({ error: "Not logged in" }, 401);
  const aff = await env.DB.prepare(
    "SELECT code, status FROM affiliates WHERE user_id = ?"
  ).bind(user.id).first();
  return json({
    email: user.email,
    name: user.name,
    isAffiliate: !!aff,
    affiliateCode: aff ? aff.code : null,
  });
}

async function joinAffiliate(request, env) {
  const user = await getUser(request, env);
  if (!user) return json({ error: "Not logged in" }, 401);
  const existing = await env.DB.prepare(
    "SELECT code FROM affiliates WHERE user_id = ?"
  ).bind(user.id).first();
  if (existing) return json({ code: existing.code });

  const code = randomHex(4).toUpperCase();
  await env.DB.prepare(
    "INSERT INTO affiliates (code, email, user_id) VALUES (?, ?, ?)"
  ).bind(code, user.email, user.id).run();
  return json({ code });
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    const method = request.method;

    try {
      if (pathname === "/api/health") return json({ ok: true });
      if (pathname === "/api/signup" && method === "POST") return await signup(request, env);
      if (pathname === "/api/login" && method === "POST") return await login(request, env);
      if (pathname === "/api/logout" && method === "POST") return await logout(request, env);
      if (pathname === "/api/me" && method === "GET") return await me(request, env);
      if (pathname === "/api/affiliate/join" && method === "POST") return await joinAffiliate(request, env);
      if (pathname.startsWith("/api/")) return json({ error: "Not found" }, 404);
    } catch (err) {
      console.error(err);
      return json({ error: "Server error" }, 500);
    }

    return env.ASSETS.fetch(request);
  },
};