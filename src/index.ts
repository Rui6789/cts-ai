interface Env {
  DB: D1Database;
  ASSETS: Fetcher;

  APP_USERNAME: string;
  APP_PASSWORD: string;
  SESSION_SECRET: string;
}

const SESSION_COOKIE = "cts_session";
const SESSION_MAX_AGE = 60 * 60 * 24 * 7; // 7 天

interface SessionPayload {
  username: string;
  exp: number;
}

/* =========================
   Base64URL
========================= */

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlToBytes(value: string): Uint8Array {
  let base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  while (base64.length % 4) {
    base64 += "=";
  }

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function encodeText(value: string): string {
  return bytesToBase64Url(
    new TextEncoder().encode(value)
  );
}

function decodeText(value: string): string {
  return new TextDecoder().decode(
    base64UrlToBytes(value)
  );
}

/* =========================
   Session 签名
========================= */

async function getSigningKey(
  secret: string
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign", "verify"]
  );
}

async function signValue(
  value: string,
  secret: string
): Promise<string> {
  const key = await getSigningKey(secret);

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  );

  return bytesToBase64Url(
    new Uint8Array(signature)
  );
}

async function verifySignature(
  value: string,
  signature: string,
  secret: string
): Promise<boolean> {
  try {
    const key = await getSigningKey(secret);

    return await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlToBytes(signature),
      new TextEncoder().encode(value)
    );
  } catch {
    return false;
  }
}

/* =========================
   创建 Session
========================= */

async function createSession(
  username: string,
  secret: string
): Promise<string> {
  const payload: SessionPayload = {
    username,
    exp: Date.now() + SESSION_MAX_AGE * 1000
  };

  const encodedPayload = encodeText(
    JSON.stringify(payload)
  );

  const signature = await signValue(
    encodedPayload,
    secret
  );

  return `${encodedPayload}.${signature}`;
}

/* =========================
   读取 Cookie
========================= */

function getCookie(
  request: Request,
  name: string
): string | null {
  const cookieHeader =
    request.headers.get("Cookie");

  if (!cookieHeader) {
    return null;
  }

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const [key, ...rest] =
      cookie.trim().split("=");

    if (key === name) {
      return rest.join("=");
    }
  }

  return null;
}

/* =========================
   验证 Session
========================= */

async function getSession(
  request: Request,
  env: Env
): Promise<SessionPayload | null> {
  const session = getCookie(
    request,
    SESSION_COOKIE
  );

  if (!session) {
    return null;
  }

  const parts = session.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [
    encodedPayload,
    signature
  ] = parts;

  const validSignature =
    await verifySignature(
      encodedPayload,
      signature,
      env.SESSION_SECRET
    );

  if (!validSignature) {
    return null;
  }

  try {
    const payload = JSON.parse(
      decodeText(encodedPayload)
    ) as SessionPayload;

    if (!payload.username || !payload.exp) {
      return null;
    }

    if (payload.exp < Date.now()) {
      return null;
    }

    if (
      payload.username !==
      env.APP_USERNAME
    ) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

/* =========================
   登录页面
========================= */

function loginPage(
  error = ""
): Response {
  const errorHtml = error
    ? `
      <div class="error">
        ${error}
      </div>
    `
    : "";

  const html = `
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta
    name="viewport"
    content="width=device-width,initial-scale=1"
  >
  <title>Login</title>
  <style>
    * { box-sizing: border-box; }
    html, body { margin: 0; width: 100%; height: 100%; }
    body {
      display: flex;
      align-items: center;
      justify-content: center;
      background: radial-gradient(circle at 50% 0%, #172033, #0a0d12 55%);
      color: #eef2f7;
      font-family: Inter, system-ui, -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
    }
    .login {
      width: min(380px, 90vw);
      padding: 36px;
      background: #10141a;
      border: 1px solid rgba(255,255,255,.08);
      border-radius: 20px;
      box-shadow: 0 30px 80px rgba(0,0,0,.4);
    }
    .kicker { color: #91a8ff; font-size: 11px; letter-spacing: .16em; font-weight: 700; }
    h1 { margin: 10px 0 26px; font-size: 28px; }
    label { display: block; margin-bottom: 7px; color: #9ca4ae; font-size: 12px; }
    input {
      width: 100%;
      margin-bottom: 18px;
      padding: 12px 14px;
      border-radius: 10px;
      border: 1px solid rgba(255,255,255,.1);
      background: #0a0d12;
      color: #eef2f7;
      outline: none;
      font-size: 14px;
    }
    input:focus { border-color: rgba(145,168,255,.45); }
    button {
      width: 100%;
      padding: 12px;
      border-radius: 10px;
      border: 1px solid rgba(145,168,255,.28);
      background: rgba(145,168,255,.1);
      color: #dbe4ff;
      cursor: pointer;
      font-weight: 650;
    }
    button:hover { background: rgba(145,168,255,.16); }
    .error {
      margin-bottom: 18px;
      padding: 10px 12px;
      border-radius: 8px;
      background: rgba(255,90,90,.08);
      color: #ffaaaa;
      font-size: 12px;
    }
  </style>
</head>
<body>
  <form class="login" method="POST" action="/login">
    <div class="kicker">CTS DIGITAL FORCE</div>
    <h1>Login</h1>
    ${errorHtml}
    <label>Username</label>
    <input name="username" type="text" autocomplete="username" required>
    <label>Password</label>
    <input name="password" type="password" autocomplete="current-password" required>
    <button type="submit">LOGIN</button>
  </form>
</body>
</html>
`;

  return new Response(
    html,
    {
      headers: {
        "Content-Type": "text/html; charset=UTF-8",
        "Cache-Control": "no-store"
      }
    }
  );
}

/* =========================
   主 Worker
========================= */

export default {
  async fetch(
    request: Request,
    env: Env
  ): Promise<Response> {
    const url = new URL(request.url);

    if (
      url.pathname === "/login" &&
      request.method === "GET"
    ) {
      const session = await getSession(request, env);
      if (session) {
        return Response.redirect(`${url.origin}/`, 302);
      }
      return loginPage();
    }

    if (
      url.pathname === "/login" &&
      request.method === "POST"
    ) {
      const form = await request.formData();
      const username = String(form.get("username") ?? "");
      const password = String(form.get("password") ?? "");

      if (
        username !== env.APP_USERNAME ||
        password !== env.APP_PASSWORD
      ) {
        return loginPage("用户名或密码错误");
      }

      const session = await createSession(username, env.SESSION_SECRET);

      return new Response(
        null,
        {
          status: 302,
          headers: {
            "Location": "/",
            "Set-Cookie":
              `${SESSION_COOKIE}=${session}; ` +
              `Path=/; ` +
              `HttpOnly; ` +
              `Secure; ` +
              `SameSite=Lax; ` +
              `Max-Age=${SESSION_MAX_AGE}`
          }
        }
      );
    }

    if (url.pathname === "/logout") {
      return new Response(
        null,
        {
          status: 302,
          headers: {
            "Location": "/login",
            "Set-Cookie":
              `${SESSION_COOKIE}=; ` +
              `Path=/; ` +
              `HttpOnly; ` +
              `Secure; ` +
              `SameSite=Lax; ` +
              `Max-Age=0`
          }
        }
      );
    }

    const session = await getSession(request, env);

    if (!session) {
      if (url.pathname.startsWith("/api/")) {
        return Response.json(
          { error: "Unauthorized" },
          { status: 401 }
        );
      }

      return new Response(
        null,
        {
          status: 302,
          headers: { "Location": "/login" }
        }
      );
    }

    if (
      url.pathname === "/api/records" &&
      request.method === "GET"
    ) {
      const result = await env.DB
        .prepare(`
          SELECT *
          FROM records
          ORDER BY id DESC
        `)
        .all();

      return Response.json(result.results);
    }

    if (
      url.pathname === "/api/records" &&
      request.method === "POST"
    ) {
      const body = await request.json<{ content: string }>();

      if (typeof body.content !== "string") {
        return Response.json(
          { error: "Invalid content" },
          { status: 400 }
        );
      }

      await env.DB
        .prepare(`
          INSERT INTO records
          (content)
          VALUES (?)
        `)
        .bind(body.content)
        .run();

      return Response.json({ success: true });
    }

    const recordMatch = url.pathname.match(/^\/api\/records\/(\d+)$/);

    if (
      recordMatch &&
      request.method === "PUT"
    ) {
      const id = Number(recordMatch[1]);
      const body = await request.json<{ content: string }>();

      if (typeof body.content !== "string") {
        return Response.json(
          { error: "Invalid content" },
          { status: 400 }
        );
      }

      await env.DB
        .prepare(`
          UPDATE records
          SET content = ?
          WHERE id = ?
        `)
        .bind(body.content, id)
        .run();

      return Response.json({ success: true });
    }

    if (
      recordMatch &&
      request.method === "DELETE"
    ) {
      const id = Number(recordMatch[1]);

      await env.DB
        .prepare(`
          DELETE FROM records
          WHERE id = ?
        `)
        .bind(id)
        .run();

      return Response.json({ success: true });
    }

    if (url.pathname.startsWith("/api/")) {
      return Response.json(
        { error: "Not Found" },
        { status: 404 }
      );
    }

    return env.ASSETS.fetch(request);
  }
};
