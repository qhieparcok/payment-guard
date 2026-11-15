// End-to-end test of the built worker (dist/worker.js): health, demo,
// screen verdicts, and the arena route (signed task, bad signature,
// missing secret, idempotent retry). Run: node test-worker-local.mjs
import worker from "./dist/worker.js";
import { createHmac } from "node:crypto";

const BASE = "https://payment-guard.parcok03.workers.dev";
const SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
// In-memory stand-in for the ARENA_KV binding (the real Worker gets
// the Cloudflare KV namespace). Shared across module instances, so a
// fresh import simulates a new isolate that still sees KV state.
const kvStore = new Map();
const KV = {
  get: async (k) => (kvStore.has(k) ? kvStore.get(k) : null),
  put: async (k, v) => { kvStore.set(k, v); },
};
const ENV = { AGENT_GAMES_HMAC_SECRET: SECRET, ARENA_KV: KV };
const NO_KV_ENV = { AGENT_GAMES_HMAC_SECRET: SECRET };
const NO_SECRET_ENV = {};

const RECIPIENT = "0xDe42000000000000000000000000000000009f01";
const OFFICIAL_VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

function taskBody(over = {}) {
  return JSON.stringify({
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_24_9d1",
    mode: "competition",
    input: {
      registered_vk: OFFICIAL_VK,
      proof_vk: OFFICIAL_VK,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0xa4c1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      ...over,
    },
  });
}

function sign(text, secret) {
  return createHmac("sha256", Buffer.from(secret, "hex")).update(text).digest("hex");
}

// Sign with the raw secret text as the key (no hex decoding) — the
// derivation the platform may use. The worker must accept it too.
function signRawKey(text, secret) {
  return createHmac("sha256", Buffer.from(secret, "utf8")).update(text).digest("hex");
}

let pass = 0;
let fail = 0;
function check(name, cond, extra = "") {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? "  " + extra : ""}`);
  if (cond) pass++; else fail++;
}

async function main() {
  // Health + demo + screen (existing routes must keep working)
  let r = await worker.fetch(new Request(BASE + "/health"), ENV);
  check("GET /health 200", r.status === 200);
  const health = await r.json();
  check("health body ok", health.status === "ok");

  r = await worker.fetch(new Request(BASE + "/demo"), ENV);
  check("GET /demo 200", r.status === 200);

  // Screen: 10 USDT to burn -> ALLOW 0
  r = await worker.fetch(
    new Request(BASE + "/screen", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chain: "bsc",
        from: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        to: "0x000000000000000000000000000000000000dEaD",
        token: "0x55d398326f99059fF775485246999027B3197955",
        amount: "10000000000000000000",
        kind: "transfer",
      }),
    }),
    ENV
  );
  const screen = await r.json();
  check("POST /screen burn transfer -> ALLOW 0", r.status === 200 && screen.decision === "ALLOW" && screen.risk_score === 0, JSON.stringify({ d: screen.decision, s: screen.risk_score }));

  // Arena: valid signed task -> APPROVE
  const goodBody = taskBody();
  r = await worker.fetch(
    new Request(BASE + "/arena/gatekeeper", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-agent-games-signature": sign(goodBody, SECRET) },
      body: goodBody,
    }),
    ENV
  );
  const arenaOk = await r.json();
  const sigOut = r.headers.get("x-agent-games-signature");
  check("arena valid task -> APPROVE", r.status === 200 && arenaOk.decision === "APPROVE" && arenaOk.reason_code === "VALID_CONDITION", JSON.stringify(arenaOk));
  check("arena response carries circuit_version", arenaOk.circuit_version === "gatekeeper-v1", JSON.stringify({ cv: arenaOk.circuit_version }));
  check("arena response is signed", typeof sigOut === "string" && /^[0-9a-f]{64}$/.test(sigOut));
  // The response signature must verify against the response body.
  const rawOk = JSON.stringify(arenaOk);
  check("arena response signature verifies", sigOut === sign(rawOk, SECRET));

  // Arena: same task_id retried -> identical body
  r = await worker.fetch(
    new Request(BASE + "/arena/gatekeeper", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-agent-games-signature": sign(goodBody, SECRET) },
      body: goodBody,
    }),
    ENV
  );
  const retry = await r.text();
  check("arena retry returns identical body", retry === rawOk);

  // Arena: trap task (amount overflow) -> REJECT.
  // Note: a fresh task_id — reusing the approved task's id would
  // correctly return the cached APPROVE (idempotency).
  const trapBody = JSON.stringify({
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_24_9d2",
    mode: "competition",
    input: {
      registered_vk: OFFICIAL_VK,
      proof_vk: OFFICIAL_VK,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: "1500",
      max_transfer: "1000",
      proof_tx: "0xa4c1cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    },
  });
  r = await worker.fetch(
    new Request(BASE + "/arena/gatekeeper", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-agent-games-signature": sign(trapBody, SECRET) },
      body: trapBody,
    }),
    ENV
  );
  const trap = await r.json();
  check("arena amount overflow -> REJECT", r.status === 200 && trap.decision === "REJECT" && trap.reason_code === "AMOUNT_OVERFLOW", JSON.stringify(trap));

  // Arena: tampered body -> 401
  const tampered = goodBody.replace("1460", "1461");
  r = await worker.fetch(
    new Request(BASE + "/arena/gatekeeper", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-agent-games-signature": sign(goodBody, SECRET) },
      body: tampered,
    }),
    ENV
  );
  check("arena tampered body -> 401", r.status === 401);

  // Arena: wrong secret -> 401
  r = await worker.fetch(
    new Request(BASE + "/arena/gatekeeper", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-agent-games-signature": sign(goodBody, "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210") },
      body: goodBody,
    }),
    ENV
  );
  check("arena wrong secret -> 401", r.status === 401);

  // Arena: no secret configured -> 401 (fail closed)
  r = await worker.fetch(
    new Request(BASE + "/arena/gatekeeper", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-agent-games-signature": sign(goodBody, SECRET) },
      body: goodBody,
    }),
    NO_SECRET_ENV
  );
  check("arena no secret configured -> 401 (fail closed)", r.status === 401);

  // Arena: missing signature header -> 401
  r = await worker.fetch(
    new Request(BASE + "/arena/gatekeeper", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: goodBody,
    }),
    ENV
  );
  check("arena missing signature -> 401", r.status === 401);

  // Arena via the registered endpoint (/screen) with a signature header
  const screenTaskBody = taskBody({ task_id: "gk_24_9d3" });
  r = await worker.fetch(
    new Request(BASE + "/screen", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-agent-games-signature": sign(screenTaskBody, SECRET) },
      body: screenTaskBody,
    }),
    ENV
  );
  const viaScreen = await r.json();
  check("arena task via POST /screen -> APPROVE", r.status === 200 && viaScreen.decision === "APPROVE", JSON.stringify(viaScreen));

  // Arena: same task signed with the RAW secret text as key -> APPROVE.
  // This is the derivation the platform may use; the worker accepts it.
  const rawKeyBody = taskBody({ task_id: "gk_24_9d4" });
  r = await worker.fetch(
    new Request(BASE + "/arena/gatekeeper", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-agent-games-signature": signRawKey(rawKeyBody, SECRET) },
      body: rawKeyBody,
    }),
    ENV
  );
  const rawKey = await r.json();
  check("arena raw-string-key signature -> APPROVE", r.status === 200 && rawKey.decision === "APPROVE", JSON.stringify(rawKey));

  // Arena: same task signed with the hex key but sent as base64 -> APPROVE.
  const b64Body = taskBody({ task_id: "gk_24_9d5" });
  const b64Sig = Buffer.from(sign(b64Body, SECRET), "hex").toString("base64");
  r = await worker.fetch(
    new Request(BASE + "/arena/gatekeeper", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-agent-games-signature": b64Sig },
      body: b64Body,
    }),
    ENV
  );
  const b64 = await r.json();
  check("arena base64 signature -> APPROVE", r.status === 200 && b64.decision === "APPROVE", JSON.stringify(b64));

  // Preflight: a signed request that is not a gatekeeper task must get
  // exactly {"ok":true,"protocolVersion":"v1"} with a valid signature
  // header — the platform's diagnostic rejects anything else as
  // "protocol" even when the request signature verified.
  const probeBody = JSON.stringify({ type: "agent-games.preflight.v1", agent: "payment-guard" });
  r = await worker.fetch(
    new Request(BASE + "/screen", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-agent-games-signature": sign(probeBody, SECRET) },
      body: probeBody,
    }),
    ENV
  );
  const probeText = await r.text();
  const probeSig = r.headers.get("x-agent-games-signature");
  const probeSigValid = probeSig === sign(probeText, SECRET);
  check("preflight probe -> signed protocol-v1 JSON", r.status === 200 && probeText === '{"ok":true,"protocolVersion":"v1"}' && probeSigValid, probeText);

  // Screen without a signature header still works as a screen request
  r = await worker.fetch(
    new Request(BASE + "/screen", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chain: "bsc",
        from: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        to: "0x000000000000000000000000000000000000dEaD",
        token: "0x55d398326f99059fF775485246999027B3197955",
        amount: "10000000000000000000",
        kind: "transfer",
      }),
    }),
    ENV
  );
  const screen2 = await r.json();
  check("POST /screen without signature still screens", r.status === 200 && screen2.decision === "ALLOW");

  // /debug-secret was a temporary diagnostic for the preflight 401;
  // the preflight passed, so the route is gone (404).
  r = await worker.fetch(new Request(BASE + "/debug-secret"), ENV);
  check("GET /debug-secret removed -> 404", r.status === 404);

  // KV unavailable: the arena must still answer from memory alone.
  // A missing KV binding must never cost a task.
  const noKvBody = taskBody({ task_id: "gk_24_9d6" });
  r = await worker.fetch(
    new Request(BASE + "/arena/gatekeeper", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-agent-games-signature": sign(noKvBody, SECRET) },
      body: noKvBody,
    }),
    NO_KV_ENV
  );
  const noKv = await r.json();
  check("arena works without KV binding (fail-safe fallback)", r.status === 200 && noKv.decision === "APPROVE", JSON.stringify(noKv));

  // Cross-isolate durability: a fresh module import has empty
  // in-memory state (new isolate) but shares the same KV. A reuse
  // trap must still be caught, and a retried task must still return
  // the identical body — both from KV, not from memory.
  const fresh = (await import("./dist/worker.js?fresh=1")).default;
  // Reuse: same proof_tx as the approved task, but a NEW task id.
  // (taskBody spreads overrides into input, so set task_id directly.)
  const reuseObj = JSON.parse(taskBody());
  reuseObj.task_id = "gk_24_9d7";
  const reuseBody = JSON.stringify(reuseObj);
  r = await fresh.fetch(
    new Request(BASE + "/arena/gatekeeper", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-agent-games-signature": sign(reuseBody, SECRET) },
      body: reuseBody,
    }),
    ENV
  );
  const reuse = await r.json();
  check("cross-isolate reuse caught via KV -> PROOF_REUSED", r.status === 200 && reuse.decision === "REJECT" && reuse.reason_code === "PROOF_REUSED", JSON.stringify(reuse));
  // Idempotency: retry the approved task on the fresh isolate.
  r = await fresh.fetch(
    new Request(BASE + "/arena/gatekeeper", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-agent-games-signature": sign(goodBody, SECRET) },
      body: goodBody,
    }),
    ENV
  );
  const retryFresh = await r.text();
  check("cross-isolate retry returns identical body via KV", retryFresh === rawOk);

  console.log(`\n${pass} passed, ${fail} failed (of ${pass + fail} checks)`);
  if (fail > 0) process.exit(1);
}

main().catch((e) => { console.error("FAILED:", e); process.exit(1); });
