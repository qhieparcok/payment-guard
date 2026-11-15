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
  ARENA_VERSION,
  GATEKEEPER_TASK_TYPE,
  decideTask,
  isGatekeeperTask,
  normalizeProofTx,
  signResponseBodyWithKey,
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
//
// NOTE (15 Nov 2026): the secret was first stored in the dashboard
// under the name `Agent_games` instead of `AGENT_GAMES_HMAC_SECRET`,
// so env.AGENT_GAMES_HMAC_SECRET was undefined and every signed
// preflight/task got 401. Accept that name as a fallback so the
// already-stored value is used; the canonical name still wins.
interface ArenaEnv {
  AGENT_GAMES_HMAC_SECRET?: string;
  Agent_games?: string;
  ARENA_KV?: KVNamespaceLike;
}

// Minimal KV namespace shape (the Worker runtime provides the real
// one; the local test passes an in-memory stand-in). Kept narrow so
// the local TypeScript build does not need @cloudflare/workers-types.
// Every KV access is best-effort and wrapped in try/catch: if KV is
// unavailable or the binding is missing, the handler falls back to
// the in-memory sets and still answers the task. KV must never cost
// a task.
interface KVNamespaceLike {
  get(key: string): Promise<string | null>;
  put(key: string, value: string): Promise<void>;
}

// KV keys. One key per proof reference and one per task id, so reads
// and writes never race each other (no read-modify-write on a shared
// list). Keys are the NORMALIZED proof reference, matching arena.ts.
const kvProofKey = (proofTxKey: string) => `proof:${proofTxKey}`;
const kvTaskKey = (taskId: string) => `task:${taskId}`;

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
  const secret = env.AGENT_GAMES_HMAC_SECRET ?? env.Agent_games;

  // No secret configured, or a bad signature: reject before parsing.
  // There is nothing to decide when the request cannot be trusted.
  // verifyTaskSignature returns the key derivation that verified, so
  // the response is signed with the same one the platform used.
  const verifiedKey = await verifyTaskSignature(rawBody, signatureHeader, secret);
  if (!verifiedKey) {
    return json({ error: "invalid or missing task signature", code: "BAD_SIGNATURE" }, 401);
  }

  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return json({ error: "body must be valid JSON", code: "INVALID_JSON" }, 400);
  }

  // A signed request that is not a gatekeeper task (for example a
  // preflight check) gets a signed protocol-v1 acknowledgement, not a
  // decision. The platform's preflight requires exactly this body:
  // {"ok":true,"protocolVersion":"v1"} — with the same field order,
  // signed with the HMAC secret. Anything else fails the diagnostic
  // as "protocol" even when the request signature verified.
  if (!isGatekeeperTask(body)) {
    const ackText = '{"ok":true,"protocolVersion":"v1"}';
    const sig = await signResponseBodyWithKey(new TextEncoder().encode(ackText), verifiedKey);
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
  const kv = env.ARENA_KV ?? null;

  // Idempotency: a retried task_id gets the exact response it got
  // the first time, signature included. The in-memory cache is
  // checked first; KV is the durable copy, so a retry that lands on
  // a fresh isolate still gets the identical body. A KV failure here
  // is not fatal — the task is simply decided again (the decision is
  // deterministic, so the recomputed body matches).
  const cached = taskResponses.get(task.task_id);
  if (cached !== undefined) {
    return new Response(cached, {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "x-agent-games-signature": await signResponseBodyWithKey(
          new TextEncoder().encode(cached),
          verifiedKey
        ),
      },
    });
  }
  if (kv) {
    try {
      const kvCached = await kv.get(kvTaskKey(task.task_id));
      if (kvCached !== null) {
        taskResponses.set(task.task_id, kvCached);
        return new Response(kvCached, {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "x-agent-games-signature": await signResponseBodyWithKey(
              new TextEncoder().encode(kvCached),
              verifiedKey
            ),
          },
        });
      }
    } catch {
      // KV read failed; fall through and decide the task normally.
    }
  }

  // Durable reuse check. The in-memory seen-set is per isolate, and
  // arena tasks arrive hours apart, so a fresh isolate would miss a
  // reuse the platform already accepted elsewhere. KV is the
  // cross-isolate memory: if this proof reference was approved
  // before, seed the in-memory set so decideTask catches it.
  const proofTxKey = normalizeProofTx(task.input?.proof_tx) ?? "";
  if (kv && proofTxKey) {
    try {
      const seenInKv = await kv.get(kvProofKey(proofTxKey));
      if (seenInKv !== null) seenProofTx.add(proofTxKey);
    } catch {
      // KV read failed; the in-memory set is all we have.
    }
  }

  const verdict: GatekeeperVerdict = decideTask(task, {
    seenProofTx,
    recordApproval: (proofTx) => {
      seenProofTx.add(proofTx);
    },
  });

  // On APPROVE, record the proof reference durably so a later task
  // reusing it is rejected even on a fresh isolate. Best-effort: a
  // KV write failure must not cost the response.
  if (kv && verdict.decision === "APPROVE" && proofTxKey) {
    try {
      await kv.put(kvProofKey(proofTxKey), "1");
    } catch {
      // The in-memory set still holds it for this isolate.
    }
  }

  // The response carries the decision, the reason, the proof
  // reference echoed back, and the circuit version. No Groth16 proof
  // is attached: proof generation needs roughly a second of
  // elliptic-curve CPU, which the free Worker plan does not allow
  // per request, so the agent answers the decision and takes the
  // missing-proof deduction instead of timing out. See
  // arena/PROTOCOL.md.
  const responseBody = JSON.stringify({
    decision: verdict.decision,
    reason_code: verdict.reason_code,
    proof_tx: verdict.proof_tx,
    circuit_version: ARENA_VERSION,
  });
  taskResponses.set(task.task_id, responseBody);
  if (kv) {
    try {
      await kv.put(kvTaskKey(task.task_id), responseBody);
    } catch {
      // The in-memory cache still holds it for this isolate.
    }
  }

  const sig = await signResponseBodyWithKey(new TextEncoder().encode(responseBody), verifiedKey);
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
