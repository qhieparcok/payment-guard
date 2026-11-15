// Unit tests for the Proof Gatekeeper arena logic: the decision
// checklist (all seven trap varieties), HMAC verification, and the
// proof-reuse seen-set. No network. Run: node --test test/*.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import {
  REGISTERED_VK_HASH,
  decideTask,
  isGatekeeperTask,
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
  assert.ok(seen.has(PROOF_TX), "approval must record the proof reference");
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
  assert.equal(await verifyTaskSignature(bodyBytes, sig, TEST_SECRET), true);
});

test("HMAC rejects a tampered body", async () => {
  const sig = await signResponseBody(bodyBytes, TEST_SECRET);
  const tampered = new TextEncoder().encode(bodyText.replace("1460", "1461"));
  assert.equal(await verifyTaskSignature(tampered, sig, TEST_SECRET), false);
});

test("HMAC rejects a wrong secret", async () => {
  const sig = await signResponseBody(bodyBytes, TEST_SECRET);
  assert.equal(await verifyTaskSignature(bodyBytes, sig, OTHER_SECRET), false);
});

test("HMAC rejects a missing secret and a missing signature", async () => {
  const sig = await signResponseBody(bodyBytes, TEST_SECRET);
  assert.equal(await verifyTaskSignature(bodyBytes, sig, undefined), false);
  assert.equal(await verifyTaskSignature(bodyBytes, null, TEST_SECRET), false);
  assert.equal(await verifyTaskSignature(bodyBytes, "", TEST_SECRET), false);
});

test("HMAC rejects a malformed signature", async () => {
  assert.equal(await verifyTaskSignature(bodyBytes, "not-hex", TEST_SECRET), false);
  assert.equal(await verifyTaskSignature(bodyBytes, "00".repeat(31), TEST_SECRET), false);
});

test("secretToKey decodes a 64-hex secret to 32 bytes", () => {
  const key = secretToKey(TEST_SECRET);
  assert.equal(key.length, 32);
  assert.equal(key[0], 0x01);
  assert.equal(key[1], 0x23);
});
