// Cloudflare Worker entry: POST /screen, POST /arena/gatekeeper,
// GET /health, GET /demo, GET /.
// Read-only by design: this agent only reads chain data and returns a
// verdict. It never sends a transaction, never asks for a key, never signs.
//
// POST /screen also accepts Proof Gatekeeper arena tasks. The platform
// posts signed task envelopes to the registered endpoint, which is
// /screen. A request that carries an x-agent-games-signature header is
// an arena task and is handled by the arena path (HMAC first, then
// decide). Anything else on /screen is a screening request, as before.

import { ScreeningEngine } from "./engine.js";
import { RpcProvider } from "./onchain.js";
import { validateScreenRequest } from "./validate.js";
import { demoHtml } from "./demo.js";
import {
  GATEKEEPER_TASK_TYPE,
  decideTask,
  isGatekeeperTask,
  signResponseBody,
  verifyTaskSignature,
} from "./arena.js";
import type { ScreenResult } from "./types.js";
import type { GatekeeperTask, GatekeeperVerdict } from "./arena.js";

const VERSION = "1.0.0";
const MAX_BODY_BYTES = 10_240;
const RATE_LIMIT_PER_MIN = 60;

const engine = new ScreeningEngine();
const provider = new RpcProvider();

// Environment bindings. AGENT_GAMES_HMAC_SECRET is the 32-byte secret
// the platform issued at agent registration (shown once). It is set
// with `wrangler secret put AGENT_GAMES_HMAC_SECRET` and is never
// committed anywhere. While it is not set, the arena route fails
// closed: every signed task is rejected.
interface ArenaEnv {
  AGENT_GAMES_HMAC_SECRET?: string;
}

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

// Proof references the agent has already accepted (approved), keyed by
// proof_tx. A proof that was only ever rejected is not "used".
// In-memory per isolate: a best-effort seen-set. Workers route requests
// across isolates, so a reuse that lands on a fresh isolate may not be
// caught locally — the platform's own ledger is the final authority.
const seenProofTx = new Set<string>();

// Responses already given, keyed by task_id. Task IDs are idempotency
// keys: the platform may retry after a network failure, and a retried
// task must get the byte-identical response it got the first time.
const taskResponses = new Map<string, string>();

function json(body: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}

function corsPreflight(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, x-agent-games-signature",
      "Access-Control-Max-Age": "86400",
    },
  });
}

async function handleScreenText(text: string): Promise<Response> {
  if (text.length > MAX_BODY_BYTES) {
    return json({ error: "body too large (max 10 KB)", code: "BODY_TOO_LARGE" }, 413);
  }
  let body: unknown;
  try {
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

// Arena task handler. rawBody is the exact request bytes; the HMAC is
// verified against them before the body is parsed.
async function handleArena(
  rawBody: Uint8Array,
  text: string,
  signatureHeader: string | null,
  env: ArenaEnv
): Promise<Response> {
  const secret = env.AGENT_GAMES_HMAC_SECRET;

  // No secret configured, or a bad signature: reject before parsing.
  // There is nothing to decide when the request cannot be trusted.
  const ok = await verifyTaskSignature(rawBody, signatureHeader, secret);
  if (!ok) {
    return json({ error: "invalid or missing task signature", code: "BAD_SIGNATURE" }, 401);
  }

  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return json({ error: "body must be valid JSON", code: "INVALID_JSON" }, 400);
  }

  // A signed request that is not a gatekeeper task (for example a
  // preflight check) gets a signed acknowledgement, not a decision.
  if (!isGatekeeperTask(body)) {
    const ack = { status: "ok", service: "payment-guard", version: VERSION, time: new Date().toISOString() };
    const ackText = JSON.stringify(ack);
    const sig = await signResponseBody(new TextEncoder().encode(ackText), secret as string);
    return new Response(ackText, {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "x-agent-games-signature": sig,
      },
    });
  }

  const task = body as GatekeeperTask;

  // Idempotency: a retried task_id gets the exact response it got
  // the first time, signature included.
  const cached = taskResponses.get(task.task_id);
  if (cached !== undefined) {
    return new Response(cached, {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "x-agent-games-signature": await signResponseBody(
          new TextEncoder().encode(cached),
          secret as string
        ),
      },
    });
  }

  const verdict: GatekeeperVerdict = decideTask(task, {
    seenProofTx,
    recordApproval: (proofTx) => {
      seenProofTx.add(proofTx);
    },
  });

  // The response carries the decision, the reason, and the proof
  // reference echoed back. No Groth16 proof is attached: proof
  // generation needs roughly a second of elliptic-curve CPU, which
  // the free Worker plan does not allow per request, so the agent
  // answers the decision and takes the missing-proof deduction
  // instead of timing out. See arena/PROTOCOL.md.
  const responseBody = JSON.stringify({
    decision: verdict.decision,
    reason_code: verdict.reason_code,
    proof_tx: verdict.proof_tx,
  });
  taskResponses.set(task.task_id, responseBody);

  const sig = await signResponseBody(new TextEncoder().encode(responseBody), secret as string);
  return new Response(responseBody, {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "x-agent-games-signature": sig,
    },
  });
}

export default {
  async fetch(req: Request, env: ArenaEnv): Promise<Response> {
    const url = new URL(req.url);
    const ip = req.headers.get("cf-connecting-ip") ?? req.headers.get("x-forwarded-for") ?? "unknown";
    if (req.method === "OPTIONS") return corsPreflight();

    if (req.method === "POST" && (url.pathname === "/screen" || url.pathname === "/arena/gatekeeper")) {
      const len = req.headers.get("content-length");
      if (len !== null && Number(len) > MAX_BODY_BYTES) {
        return json({ error: "body too large (max 10 KB)", code: "BODY_TOO_LARGE" }, 413);
      }
      const rawBody = new Uint8Array(await req.arrayBuffer());
      if (rawBody.length > MAX_BODY_BYTES) {
        return json({ error: "body too large (max 10 KB)", code: "BODY_TOO_LARGE" }, 413);
      }
      const text = new TextDecoder().decode(rawBody);
      const signatureHeader = req.headers.get("x-agent-games-signature");

      // A signed request is an arena task, whichever of the two
      // routes it arrived on. The registered endpoint is /screen.
      if (signatureHeader !== null || url.pathname === "/arena/gatekeeper") {
        return handleArena(rawBody, text, signatureHeader, env);
      }
      if (rateLimited(ip)) return json({ error: "rate limited (60/min)", code: "RATE_LIMITED" }, 429);
      return handleScreenText(text);
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
          "POST /screen": "screen a transfer or approval before signing; also accepts signed Proof Gatekeeper arena tasks",
          "POST /arena/gatekeeper": "Proof Gatekeeper arena tasks (signed)",
          "GET /health": "health check",
          "GET /demo": "interactive demo (ALLOW / WARN / BLOCK examples)",
        },
        demo: "/demo",
      });
    }
    return json({ error: "not found", code: "NOT_FOUND" }, 404);
  },
};
