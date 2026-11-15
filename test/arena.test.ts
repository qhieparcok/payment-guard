// Unit tests for the Proof Gatekeeper arena logic: the decision
// checklist (all seven trap varieties), HMAC verification, and the
// proof-reuse seen-set. No network. Run: node --test test/*.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import {
  GATEKEEPER_TASK_TYPE,
  REGISTERED_VK_HASH,
  decideTask,
  isGatekeeperTask,
  normalizeProofTx,
  secretToKey,
  signResponseBody,
  verifyTaskSignature,
} from "../dist/arena.js";
import type { DecisionContext, GatekeeperTask } from "../dist/arena.js";

const OFFICIAL_VK = REGISTERED_VK_HASH;
const OTHER_VK = "0xa4c1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RECIPIENT = "0xDe42000000000000000000000000000000009f01";
const OTHER_ADDR = "0x1111111111111111111111111111111111111111";
const PROOF_TX = "0xa4c1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

function task(over: { input?: Record<string, unknown>; task_id?: string } = {}): GatekeeperTask {
  const { input: inputOver, ...rest } = over;
  return {
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
      proof_tx: PROOF_TX,
      ...(inputOver ?? {}),
    },
    ...rest,
  } as GatekeeperTask;
}

function freshCtx(): { ctx: DecisionContext; seen: Set<string> } {
  const seen = new Set<string>();
  return {
    seen,
    ctx: {
      seenProofTx: seen,
      recordApproval: (proofTx: string) => {
        seen.add(proofTx);
      },
    },
  };
}

// --- Decision checklist: one test per trap variety ---

test("valid condition approves and records the proof reference", () => {
  const { ctx, seen } = freshCtx();
  const v = decideTask(task(), ctx);
  assert.equal(v.decision, "APPROVE");
  assert.equal(v.reason_code, "VALID_CONDITION");
  assert.equal(v.proof_tx, PROOF_TX);
  // The seen-set is keyed on the NORMALIZED reference (no 0x prefix,
  // lowercase), so the same proof in another casing is still caught.
  assert.ok(seen.has(normalizeProofTx(PROOF_TX)), "approval must record the proof reference");
});

test("balance exactly at the minimum still approves", () => {
  const { ctx } = freshCtx();
  const v = decideTask(task({ input: { public_balance: "1000" } }), ctx);
  assert.equal(v.decision, "APPROVE");
});

test("amount exactly at the cap still approves", () => {
  const { ctx } = freshCtx();
  const v = decideTask(task({ input: { amount: "1000" } }), ctx);
  assert.equal(v.decision, "APPROVE");
});

test("VK substitution rejects", () => {
  const { ctx } = freshCtx();
  const v = decideTask(task({ input: { proof_vk: OTHER_VK } }), ctx);
  assert.equal(v.decision, "REJECT");
  assert.equal(v.reason_code, "VK_SUBSTITUTION");
});

test("two equal but unregistered keys reject (VK substitution)", () => {
  const { ctx } = freshCtx();
  const v = decideTask(
    task({ input: { registered_vk: OTHER_VK, proof_vk: OTHER_VK } }),
    ctx
  );
  assert.equal(v.decision, "REJECT");
  assert.equal(v.reason_code, "VK_SUBSTITUTION");
});

test("threshold mismatch rejects", () => {
  const { ctx } = freshCtx();
  const v = decideTask(task({ input: { public_balance: "900" } }), ctx);
  assert.equal(v.decision, "REJECT");
  assert.equal(v.reason_code, "THRESHOLD_MISMATCH");
});

test("proof reuse rejects and returns no approval", () => {
  const { ctx } = freshCtx();
  const first = decideTask(task(), ctx);
  assert.equal(first.decision, "APPROVE");
  // Same proof reference, different task id: a reuse trap.
  const second = decideTask(task({ task_id: "gk_24_9d2" }), ctx);
  assert.equal(second.decision, "REJECT");
  assert.equal(second.reason_code, "PROOF_REUSED");
});

test("a proof from a rejected task is not treated as reused", () => {
  const { ctx } = freshCtx();
  const first = decideTask(task({ input: { public_balance: "900" } }), ctx);
  assert.equal(first.decision, "REJECT");
  // Same proof reference in a fresh, valid task: the earlier rejection
  // did not accept the proof, so this is not reuse.
  const second = decideTask(task({ task_id: "gk_24_9d2" }), ctx);
  assert.equal(second.decision, "APPROVE");
});

test("expired condition rejects", () => {
  const { ctx } = freshCtx();
  const v = decideTask(task({ input: { current_block: 19842201 } }), ctx);
  assert.equal(v.decision, "REJECT");
  assert.equal(v.reason_code, "EXPIRED_CONDITION");
});

test("condition at the expiry block itself is expired (fail closed)", () => {
  const { ctx } = freshCtx();
  const v = decideTask(
    task({ input: { expiry_block: 19832000, current_block: 19832000 } }),
    ctx
  );
  assert.equal(v.decision, "REJECT");
  assert.equal(v.reason_code, "EXPIRED_CONDITION");
});

test("recipient mismatch rejects", () => {
  const { ctx } = freshCtx();
  const v = decideTask(task({ input: { recipient: OTHER_ADDR } }), ctx);
  assert.equal(v.decision, "REJECT");
  assert.equal(v.reason_code, "RECIPIENT_MISMATCH");
});

test("recipient comparison is case-insensitive", () => {
  const { ctx } = freshCtx();
  const v = decideTask(
    task({ input: { recipient: RECIPIENT.toLowerCase() } }),
    ctx
  );
  assert.equal(v.decision, "APPROVE");
});

test("recipient matches without the 0x prefix", () => {
  const { ctx } = freshCtx();
  const v = decideTask(
    task({ input: { recipient: RECIPIENT.slice(2), condition_recipient: RECIPIENT } }),
    ctx
  );
  assert.equal(v.decision, "APPROVE");
});

test("VK matches without the 0x prefix", () => {
  const { ctx } = freshCtx();
  const v = decideTask(
    task({
      input: {
        registered_vk: OFFICIAL_VK.slice(2),
        proof_vk: OFFICIAL_VK.slice(2).toUpperCase(),
      },
    }),
    ctx
  );
  assert.equal(v.decision, "APPROVE");
});

test("proof reuse is caught when the second submission uses different casing", () => {
  const { ctx } = freshCtx();
  const first = decideTask(task(), ctx);
  assert.equal(first.decision, "APPROVE");
  // Same proof reference, checksummed/uppercased: the normalized
  // seen-set key must still catch it, or the agent would wrongly
  // approve a reused proof (-6, the worst penalty).
  const second = decideTask(
    task({ task_id: "gk_24_9d2", input: { proof_tx: PROOF_TX.toUpperCase() } }),
    ctx
  );
  assert.equal(second.decision, "REJECT");
  assert.equal(second.reason_code, "PROOF_REUSED");
});

test("the verdict echoes the raw proof reference, as sent", () => {
  const { ctx } = freshCtx();
  const v = decideTask(
    task({ input: { proof_tx: PROOF_TX.toUpperCase() } }),
    ctx
  );
  assert.equal(v.decision, "APPROVE");
  assert.equal(v.proof_tx, PROOF_TX.toUpperCase());
});

test("amount overflow rejects", () => {
  const { ctx } = freshCtx();
  const v = decideTask(task({ input: { amount: "1500" } }), ctx);
  assert.equal(v.decision, "REJECT");
  assert.equal(v.reason_code, "AMOUNT_OVERFLOW");
});

test("first mismatch wins when several traps are present", () => {
  const { ctx } = freshCtx();
  // Both threshold and recipient are wrong; threshold is checked first.
  const v = decideTask(
    task({ input: { public_balance: "900", recipient: OTHER_ADDR } }),
    ctx
  );
  assert.equal(v.reason_code, "THRESHOLD_MISMATCH");
});

// --- Envelope shape ---

test("isGatekeeperTask accepts the real envelope and rejects the rest", () => {
  assert.equal(isGatekeeperTask(task()), true);
  assert.equal(isGatekeeperTask({ type: "other", task_id: "x", input: {} }), false);
  assert.equal(isGatekeeperTask({ type: "agent-games.proof-gatekeeper.v1", input: {} }), false);
  assert.equal(isGatekeeperTask(null), false);
  assert.equal(isGatekeeperTask("nope"), false);
});

// --- HMAC ---

// A fixed test-only secret (64 hex chars = 32 bytes). Not a real secret.
const TEST_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OTHER_SECRET = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

const bodyText = JSON.stringify(task());
const bodyBytes = new TextEncoder().encode(bodyText);

test("HMAC verifies a correct signature", async () => {
  const sig = await signResponseBody(bodyBytes, TEST_SECRET);
  assert.match(sig, /^[0-9a-f]{64}$/);
  const key = await verifyTaskSignature(bodyBytes, sig, TEST_SECRET);
  assert.ok(key);
  assert.deepEqual(key, secretToKey(TEST_SECRET));
});

test("HMAC rejects a tampered body", async () => {
  const sig = await signResponseBody(bodyBytes, TEST_SECRET);
  const tampered = new TextEncoder().encode(bodyText.replace("1460", "1461"));
  assert.equal(await verifyTaskSignature(tampered, sig, TEST_SECRET), null);
});

test("HMAC rejects a wrong secret", async () => {
  const sig = await signResponseBody(bodyBytes, TEST_SECRET);
  assert.equal(await verifyTaskSignature(bodyBytes, sig, OTHER_SECRET), null);
});

test("HMAC rejects a missing secret and a missing signature", async () => {
  const sig = await signResponseBody(bodyBytes, TEST_SECRET);
  assert.equal(await verifyTaskSignature(bodyBytes, sig, undefined), null);
  assert.equal(await verifyTaskSignature(bodyBytes, null, TEST_SECRET), null);
  assert.equal(await verifyTaskSignature(bodyBytes, "", TEST_SECRET), null);
});

test("HMAC rejects a malformed signature", async () => {
  assert.equal(await verifyTaskSignature(bodyBytes, "not-hex", TEST_SECRET), null);
  assert.equal(await verifyTaskSignature(bodyBytes, "00".repeat(31), TEST_SECRET), null);
});

// The platform's key derivation is not documented: it may sign with
// the hex-decoded bytes, the raw secret text, or base64-decoded bytes.
// All three must verify, and the returned key must be the one used.
test("HMAC verifies a signature made with the raw secret text as key", async () => {
  const rawKey = new TextEncoder().encode(TEST_SECRET);
  const sig = await hmacHexForTest(rawKey, bodyBytes);
  const key = await verifyTaskSignature(bodyBytes, sig, TEST_SECRET);
  assert.ok(key);
  assert.deepEqual(key, rawKey);
});

test("HMAC verifies a base64-encoded signature", async () => {
  const sigHex = await signResponseBody(bodyBytes, TEST_SECRET);
  const bytes = Uint8Array.from(sigHex.match(/../g)!, (h) => parseInt(h, 16));
  const sigB64 = btoa(String.fromCharCode(...bytes));
  const key = await verifyTaskSignature(bodyBytes, sigB64, TEST_SECRET);
  assert.ok(key);
  assert.deepEqual(key, secretToKey(TEST_SECRET));
});

test("HMAC verifies a signature over canonical JSON when the body is not canonical", async () => {
  // The raw body below has its keys in a different order than the
  // canonical (sorted) form. Sign the canonical form; the worker
  // must still verify it against the raw body it received.
  const raw = JSON.stringify({ input: task().input, mode: "competition", type: GATEKEEPER_TASK_TYPE, task_id: task().task_id });
  const canonical = canonicalize(JSON.parse(raw));
  const sig = await signResponseBody(new TextEncoder().encode(canonical), TEST_SECRET);
  const key = await verifyTaskSignature(new TextEncoder().encode(raw), sig, TEST_SECRET);
  assert.ok(key);
});

// Canonical JSON (sorted keys, compact) used only by the test above
// to build the form a canonicalising signer would produce.
function canonicalize(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  if (v !== null && typeof v === "object") {
    const entries = Object.keys(v as Record<string, unknown>)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalize((v as Record<string, unknown>)[k])}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(v);
}

// Small local helper so the raw-key test does not depend on arena's
// signing path (which always uses the hex-decoded key).
async function hmacHexForTest(key: Uint8Array, body: Uint8Array): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, body);
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

test("secretToKey decodes a 64-hex secret to 32 bytes", () => {
  const key = secretToKey(TEST_SECRET);
  assert.equal(key.length, 32);
  assert.equal(key[0], 0x01);
  assert.equal(key[1], 0x23);
});
