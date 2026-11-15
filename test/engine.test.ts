// Unit tests for the screening engine + validation. Every rule gets a
// pass-case and a trigger-case. No network: the provider is a mock that
// returns canned on-chain facts. Run: node --test test/*.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import { ScreeningEngine } from "../dist/engine.js";
import { validateScreenRequest, toChecksumAddress } from "../dist/validate.js";
import type { OnChainFacts, OnChainProvider, ScreenRequest } from "../src/types.js";

const EOA = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
const BURN = "0x000000000000000000000000000000000000dEaD";
const USDT_BSC = "0x55d398326f99059fF775485246999027B3197955";
const PANCAKE = "0x10ED43C718714eb63d5aA57B78B54704E256024E";
const UNKNOWN_SPENDER = "0x1111111111111111111111111111111111111111";
const SCAM = "0x70305b080efc49eb5dfb9bda78aea516c398f804"; // documented phishing contract
const UNLIMITED = "115792089237316195423570985008687907853269984665640564039457584007913129639935"; // 2^256-1

function mockProvider(facts: Partial<OnChainFacts>): OnChainProvider {
  const base: OnChainFacts = {
    to_is_contract: false,
    to_verified: null,
    to_age_hours: null,
    token_symbol: "USDT",
    token_decimals: 18,
    from_balance: "100000000000000000000", // 100 tokens
    current_allowance: "0",
    data_unavailable: false,
  };
  return { getFacts: async () => ({ ...base, ...facts }) };
}

function transfer(over: Partial<ScreenRequest> = {}): ScreenRequest {
  return {
    chain: "bsc",
    from: EOA,
    to: BURN,
    token: USDT_BSC,
    amount: "10000000000000000000", // 10 tokens
    kind: "transfer",
    spender: null,
    approval_amount: null,
    ...over,
  };
}

function approval(over: Partial<ScreenRequest> = {}): ScreenRequest {
  return transfer({ kind: "approval", to: USDT_BSC, spender: PANCAKE, approval_amount: "10000000000000000000", ...over });
}

test("EIP-55 checksum vectors", () => {
  const cases: Array<[string, string]> = [
    ["0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"],
    ["0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"],
    ["0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb", "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"],
    ["0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"],
    ["0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae", "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"],
  ];
  for (const [input, want] of cases) assert.equal(toChecksumAddress(input), want);
  assert.equal(toChecksumAddress("not-an-address"), null);
  assert.equal(toChecksumAddress("0x1234"), null);
});

test("validation rejects bad input", () => {
  assert.equal(validateScreenRequest(null).ok, false);
  assert.equal(validateScreenRequest({ ...transfer(), to: "0x123" }).ok, false);
  assert.equal(validateScreenRequest({ ...transfer(), amount: "1.5" }).ok, false);
  assert.equal(validateScreenRequest({ ...transfer(), amount: "-5" }).ok, false);
  assert.equal(validateScreenRequest({ ...transfer(), chain: "solana" }).ok, false);
  assert.equal(validateScreenRequest({ ...transfer(), extra: 1 }).ok, false);
  assert.equal(validateScreenRequest({ ...approval(), spender: null }).ok, false);
  assert.equal(validateScreenRequest({ ...transfer(), spender: PANCAKE }).ok, false);
  const good = validateScreenRequest(transfer());
  assert.equal(good.ok, true);
});

test("clean transfer to an EOA -> ALLOW, score 0", async () => {
  const r = await new ScreeningEngine().screen(transfer(), mockProvider({}));
  assert.equal(r.decision, "ALLOW");
  assert.equal(r.risk_score, 0);
  assert.deepEqual(r.reasons.map((x) => x.code), ["OK"]);
});

test("transfer to a deny-listed address -> BLOCK / SCAM_ADDRESS", async () => {
  const r = await new ScreeningEngine().screen(transfer({ to: SCAM }), mockProvider({}));
  assert.equal(r.decision, "BLOCK");
  assert.equal(r.risk_score, 100);
  assert.ok(r.reasons.some((x) => x.code === "SCAM_ADDRESS"));
});

test("approval to a deny-listed spender -> BLOCK / RISKY_SPENDER", async () => {
  const r = await new ScreeningEngine().screen(approval({ spender: SCAM }), mockProvider({}));
  assert.equal(r.decision, "BLOCK");
  assert.ok(r.reasons.some((x) => x.code === "RISKY_SPENDER"));
});

test("unlimited approval to an unknown spender -> BLOCK", async () => {
  const r = await new ScreeningEngine().screen(
    approval({ spender: UNKNOWN_SPENDER, approval_amount: UNLIMITED }),
    mockProvider({}),
  );
  assert.equal(r.decision, "BLOCK");
  assert.ok(r.reasons.some((x) => x.code === "UNLIMITED_APPROVAL_RISKY"));
});

test("unlimited approval to a known router -> WARN, not BLOCK", async () => {
  const r = await new ScreeningEngine().screen(
    approval({ spender: PANCAKE, approval_amount: UNLIMITED }),
    mockProvider({}),
  );
  assert.equal(r.decision, "WARN");
  assert.ok(r.reasons.some((x) => x.code === "UNLIMITED_APPROVAL_KNOWN_SPENDER"));
});

test("limited approval to a known router -> ALLOW", async () => {
  const r = await new ScreeningEngine().screen(approval({}), mockProvider({}));
  assert.equal(r.decision, "ALLOW");
});

test("transfer to an unverified contract -> WARN / UNVERIFIED_CONTRACT", async () => {
  const r = await new ScreeningEngine().screen(
    transfer({ to: "0x1234567890abcdef1234567890abcdef12345678" }),
    mockProvider({ to_is_contract: true, to_verified: false, to_age_hours: 500 }),
  );
  assert.equal(r.decision, "WARN");
  assert.ok(r.reasons.some((x) => x.code === "UNVERIFIED_CONTRACT"));
  assert.ok(!r.reasons.some((x) => x.code === "NEW_CONTRACT"));
});

test("transfer to a brand-new verified contract -> WARN / NEW_CONTRACT", async () => {
  const r = await new ScreeningEngine().screen(
    transfer({ to: "0x1234567890abcdef1234567890abcdef12345678" }),
    mockProvider({ to_is_contract: true, to_verified: true, to_age_hours: 5 }),
  );
  assert.equal(r.decision, "WARN");
  assert.ok(r.reasons.some((x) => x.code === "NEW_CONTRACT"));
});

test("transfer to an old verified contract -> ALLOW", async () => {
  const r = await new ScreeningEngine().screen(
    transfer({ to: "0x1234567890abcdef1234567890abcdef12345678" }),
    mockProvider({ to_is_contract: true, to_verified: true, to_age_hours: 5000 }),
  );
  assert.equal(r.decision, "ALLOW");
});

test("zero amount -> WARN / ZERO_AMOUNT", async () => {
  const r = await new ScreeningEngine().screen(transfer({ amount: "0" }), mockProvider({}));
  assert.equal(r.decision, "WARN");
  assert.ok(r.reasons.some((x) => x.code === "ZERO_AMOUNT"));
});

test("dust amount -> WARN / DUST_AMOUNT", async () => {
  const r = await new ScreeningEngine().screen(transfer({ amount: "1" }), mockProvider({}));
  assert.equal(r.decision, "WARN");
  assert.ok(r.reasons.some((x) => x.code === "DUST_AMOUNT"));
});

test("amount above balance -> WARN / INSUFFICIENT_BALANCE", async () => {
  const r = await new ScreeningEngine().screen(
    transfer({ amount: "1000000000000000000000" }), // 1000 tokens, balance is 100
    mockProvider({}),
  );
  assert.equal(r.decision, "WARN");
  assert.ok(r.reasons.some((x) => x.code === "INSUFFICIENT_BALANCE"));
});

test("on-chain data unavailable -> WARN / DATA_UNAVAILABLE (fail-closed)", async () => {
  const r = await new ScreeningEngine().screen(transfer(), mockProvider({ data_unavailable: true }));
  assert.equal(r.decision, "WARN");
  assert.ok(r.reasons.some((x) => x.code === "DATA_UNAVAILABLE"));
});

test("contract with unknown verification -> WARN (fail-closed)", async () => {
  const r = await new ScreeningEngine().screen(
    transfer({ to: "0x1234567890abcdef1234567890abcdef12345678" }),
    mockProvider({ to_is_contract: true, to_verified: null, to_age_hours: null }),
  );
  assert.equal(r.decision, "WARN");
  assert.ok(r.reasons.some((x) => x.code === "DATA_UNAVAILABLE"));
});

test("risk score adds weights and caps at 100", async () => {
  const r = await new ScreeningEngine().screen(
    transfer({ to: SCAM, amount: "0" }),
    mockProvider({ data_unavailable: true }),
  );
  assert.equal(r.decision, "BLOCK");
  assert.equal(r.risk_score, 100); // 100 + 15 + 25 would be 140, capped at 100
  assert.ok(r.reasons.some((x) => x.code === "SCAM_ADDRESS"));
  assert.ok(r.reasons.some((x) => x.code === "ZERO_AMOUNT"));
});

test("seen-set flags a repeated identical request", async () => {
  const engine = new ScreeningEngine();
  const first = await engine.screen(transfer(), mockProvider({}));
  const second = await engine.screen(transfer(), mockProvider({}));
  assert.equal(first.facts.seen_before, false);
  assert.equal(second.facts.seen_before, true);
  assert.equal(first.request_id, second.request_id);
});
