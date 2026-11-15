// Cloudflare Worker entry: POST /screen, GET /health, GET /demo, GET /.
// Read-only by design: this agent only reads chain data and returns a
// verdict. It never sends a transaction, never asks for a key, never signs.

import { ScreeningEngine } from "./engine.js";
import { RpcProvider } from "./onchain.js";
import { validateScreenRequest } from "./validate.js";
import { demoHtml } from "./demo.js";
import type { ScreenResult } from "./types.js";

const VERSION = "1.0.0";
const MAX_BODY_BYTES = 10_240;
const RATE_LIMIT_PER_MIN = 60;

const engine = new ScreeningEngine();
const provider = new RpcProvider();

// Best-effort per-IP rate limit (in-memory, per isolate). Returns true when
// the caller is over the limit.
const hits = new Map<string, { count: number; windowStart: number }>();
function rateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = hits.get(ip);
  if (!entry || now - entry.windowStart >= 60_000) {
    hits.set(ip, { count: 1, windowStart: now });
    return false;
  }
  entry.count += 1;
  return entry.count > RATE_LIMIT_PER_MIN;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store",
    },
  });
}

function corsPreflight(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
    },
  });
}

async function handleScreen(req: Request): Promise<Response> {
  const len = req.headers.get("content-length");
  if (len !== null && Number(len) > MAX_BODY_BYTES) {
    return json({ error: "body too large (max 10 KB)", code: "BODY_TOO_LARGE" }, 413);
  }
  let body: unknown;
  try {
    const text = await req.text();
    if (text.length > MAX_BODY_BYTES) {
      return json({ error: "body too large (max 10 KB)", code: "BODY_TOO_LARGE" }, 413);
    }
    body = JSON.parse(text);
  } catch {
    return json({ error: "body must be valid JSON", code: "INVALID_JSON" }, 400);
  }
  const v = validateScreenRequest(body);
  if (!v.ok) {
    return json({ error: v.error, code: "INVALID_INPUT", field: v.field }, 400);
  }
  const result: ScreenResult = await engine.screen(v.req, provider);
  return json(result);
}

function handleHealth(): Response {
  return json({ status: "ok", service: "payment-guard", version: VERSION, time: new Date().toISOString() });
}

export default {
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const ip = req.headers.get("cf-connecting-ip") ?? req.headers.get("x-forwarded-for") ?? "unknown";
    if (req.method === "OPTIONS") return corsPreflight();
    if (url.pathname === "/screen" && req.method === "POST") {
      if (rateLimited(ip)) return json({ error: "rate limited (60/min)", code: "RATE_LIMITED" }, 429);
      return handleScreen(req);
    }
    if (url.pathname === "/health" && req.method === "GET") return handleHealth();
    if (url.pathname === "/demo" && req.method === "GET") {
      return new Response(demoHtml, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
    }
    if (url.pathname === "/" && req.method === "GET") {
      return json({
        service: "Payment & Wallet Security Guard",
        version: VERSION,
        track: "zkVerify Agent Games — Wildcard",
        endpoints: {
          "POST /screen": "screen a transfer or approval before signing",
          "GET /health": "health check",
          "GET /demo": "interactive demo (ALLOW / WARN / BLOCK examples)",
        },
        demo: "/demo",
      });
    }
    return json({ error: "not found", code: "NOT_FOUND" }, 404);
  },
};
