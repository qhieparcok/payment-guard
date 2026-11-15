// Live integration tests: real read-only calls against public mainnet
// RPCs + Blockscout. NOTHING is sent on-chain here (no transactions,
// no signatures). These are slower and can fail if a public RPC is down;
// they verify the provider works against the real chain, not just mocks.
// Run: node --test test/live.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import { ScreeningEngine } from "../dist/engine.js";
import { RpcProvider } from "../dist/onchain.js";

const EOA = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
const BURN = "0x000000000000000000000000000000000000dEaD";
const USDT_BSC = "0x55d398326f99059fF775485246999027B3197955";
const USDT_ETH = "0xdAC17F958D2ee523a2206206994597C13D831EC7";
const PANCAKE = "0x10ED43C718714eb63d5aA57B78B54704E256024E";
const UNKNOWN_SPENDER = "0x1111111111111111111111111111111111111111";
const UNLIMITED = "115792089237316195423570985008687907853269984665640564039457584007913129639935";

const provider = new RpcProvider();
const engine = new ScreeningEngine();

// Public RPCs can be slow; give each live test a generous budget.
const OPTS = { timeout: 30_000 };

test("USDT BSC is a contract, burn address is an EOA", OPTS, async () => {
  const contract = await provider.getFacts({
    chain: "bsc", from: EOA, to: USDT_BSC, token: "native",
    amount: "1", kind: "transfer", spender: null, approval_amount: null,
  });
  assert.equal(contract.to_is_contract, true);
  const eoa = await provider.getFacts({
    chain: "bsc", from: EOA, to: BURN, token: "native",
    amount: "1", kind: "transfer", spender: null, approval_amount: null,
  });
  assert.equal(eoa.to_is_contract, false);
});

test("USDT ETH is verified on Blockscout", OPTS, async () => {
  const facts = await provider.getFacts({
    chain: "eth", from: EOA, to: USDT_ETH, token: "native",
    amount: "1", kind: "transfer", spender: null, approval_amount: null,
  });
  assert.equal(facts.to_is_contract, true);
  // Blockscout should confirm USDT is a verified contract. If the explorer
  // is unreachable the fact is null (fail-closed) rather than a wrong value.
  assert.ok(facts.to_verified === true || facts.to_verified === null);
  if (facts.to_verified !== null) assert.equal(facts.to_verified, true);
});

test("DEMO 1 — transfer 10 USDT (BSC) to the burn address -> ALLOW", OPTS, async () => {
  const t0 = Date.now();
  const r = await engine.screen(
    { chain: "bsc", from: EOA, to: BURN, token: USDT_BSC, amount: "10000000000000000000", kind: "transfer", spender: null, approval_amount: null },
    provider,
  );
  const ms = Date.now() - t0;
  console.log("  demo ALLOW:", r.decision, "score", r.risk_score, "in", ms, "ms");
  assert.equal(r.decision, "ALLOW");
  assert.ok(ms < 10_000, "screen should answer in well under 10s");
});

test("DEMO 2 — unlimited USDT approval to PancakeSwap router -> WARN", OPTS, async () => {
  const r = await engine.screen(
    { chain: "bsc", from: EOA, to: USDT_BSC, token: USDT_BSC, amount: "10000000000000000000", kind: "approval", spender: PANCAKE, approval_amount: UNLIMITED },
    provider,
  );
  console.log("  demo WARN:", r.decision, "score", r.risk_score, r.reasons.map((x) => x.code).join(","));
  assert.equal(r.decision, "WARN");
  assert.ok(r.reasons.some((x) => x.code === "UNLIMITED_APPROVAL_KNOWN_SPENDER"));
});

test("DEMO 3 — unlimited USDT approval to an unknown spender -> BLOCK", OPTS, async () => {
  const r = await engine.screen(
    { chain: "bsc", from: EOA, to: USDT_BSC, token: USDT_BSC, amount: "10000000000000000000", kind: "approval", spender: UNKNOWN_SPENDER, approval_amount: UNLIMITED },
    provider,
  );
  console.log("  demo BLOCK:", r.decision, "score", r.risk_score, r.reasons.map((x) => x.code).join(","));
  assert.equal(r.decision, "BLOCK");
  assert.ok(r.reasons.some((x) => x.code === "UNLIMITED_APPROVAL_RISKY"));
});

test("transfer to a documented phishing contract -> BLOCK (live)", OPTS, async () => {
  const r = await engine.screen(
    { chain: "eth", from: EOA, to: "0x70305b080efc49eb5dfb9bda78aea516c398f804", token: "native", amount: "1000000000000000000", kind: "transfer", spender: null, approval_amount: null },
    provider,
  );
  console.log("  phishing contract:", r.decision, "score", r.risk_score, r.reasons.map((x) => x.code).join(","));
  assert.equal(r.decision, "BLOCK");
  assert.ok(r.reasons.some((x) => x.code === "SCAM_ADDRESS"));
});
