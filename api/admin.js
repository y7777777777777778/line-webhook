import crypto from "crypto";

const COOKIE_NAME = "admin_session";
const SESSION_SECONDS = 60 * 60 * 12; // 12時間

function sign(value, secret) {
  return crypto.createHmac("sha256", secret).update(value).digest("hex");
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function createSession(secret) {
  const payload = String(Date.now() + SESSION_SECONDS * 1000);
  return payload + "." + sign(payload, secret);
}

function verifySession(token, secret) {
  if (!token) return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const payload = parts[0];
  const signature = parts[1];
  if (!safeEqual(signature, sign(payload, secret))) return false;
  return Number(payload) > Date.now();
}

function getCookie(req, name) {
  const header = req.headers.cookie || "";
  const items = header.split(";");
  for (const item of items) {
    const pair = item.trim().split("=");
    if (pair[0] === name) {
      return pair.slice(1).join("=");
    }
  }
  return "";
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  const password = process.env.ADMIN_PASSWORD;
  const gasUrl = process.env.GAS_WEBHOOK_URL;
  const gasToken = process.env.GAS_ADMIN_TOKEN;

  if (!password || !gasUrl || !gasToken) {
    console.error("admin api: environment variables are not set");
    return res.status(500).json({ ok: false, error: "server not configured" });
  }

  const secret = password + ":" + gasToken;
  const action = req.query.action;

  try {

    // ログイン
    if (action === "login") {
      if (req.method !== "POST") {
        return res.status(405).json({ ok: false, error: "method not allowed" });
      }

      const input = req.body && req.body.password;

      if (!input || !safeEqual(input, password)) {
        // 総当たり対策として少し待たせる
        await sleep(1000);
        return res.status(401).json({ ok: false, error: "invalid password" });
      }

      const token = createSession(secret);
      res.setHeader(
        "Set-Cookie",
        COOKIE_NAME + "=" + token +
        "; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=" + SESSION_SECONDS
      );
      return res.status(200).json({ ok: true });
    }

    // ログアウト
    if (action === "logout") {
      res.setHeader(
        "Set-Cookie",
        COOKIE_NAME + "=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
      );
      return res.status(200).json({ ok: true });
    }

    // ここから先はログイン必須
    if (!verifySession(getCookie(req, COOKIE_NAME), secret)) {
      return res.status(401).json({ ok: false, error: "unauthorized" });
    }

    // 問い合わせ一覧
    if (action === "list") {
      if (req.method !== "GET") {
        return res.status(405).json({ ok: false, error: "method not allowed" });
      }

      const url =
        gasUrl + "?action=list&token=" + encodeURIComponent(gasToken);

      const response = await fetch(url, { redirect: "follow" });
      const data = await response.json();

      if (!data.ok) {
        console.error("admin api: GAS returned an error", data.error);
        return res.status(502).json({ ok: false, error: "upstream error" });
      }

      return res.status(200).json(data);
    }

    // ステータス変更
    if (action === "status") {
      if (req.method !== "POST") {
        return res.status(405).json({ ok: false, error: "method not allowed" });
      }

      const id = Number(req.body && req.body.id);
      const status = req.body && req.body.status;
      const allowed = ["未対応", "対応中", "対応済み"];

      if (!Number.isInteger(id) || id < 2 || !allowed.includes(status)) {
        return res.status(400).json({ ok: false, error: "bad request" });
      }

      const response = await fetch(gasUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "setStatus", token: gasToken, id, status }),
        redirect: "follow"
      });
      const data = await response.json();

      if (!data.ok) {
        console.error("admin api: GAS returned an error", data.error);
        return res.status(502).json({ ok: false, error: "upstream error" });
      }

      return res.status(200).json({ ok: true, id, status });
    }

    return res.status(400).json({ ok: false, error: "unknown action" });

  } catch (error) {
    console.error("admin api error:", error);
    return res.status(500).json({ ok: false, error: "internal error" });
  }
}
