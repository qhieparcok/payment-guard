# Payment & Wallet Security Guard

**zkVerify Agent Games — Wildcard track.**

An agent that screens a crypto transfer or token approval **before you sign it**, and answers **ALLOW / WARN / BLOCK** with reasons you can verify. It only reads the chain. It never sends a transaction, never asks for a private key, and never signs anything.

Live endpoint: `https://payment-guard.parcok03.workers.dev` *(live since 15 Nov 2026, verified: /health 200, /demo 200, /screen ALLOW 0 / WARN 35 / BLOCK 85)*

## The problem

The two most expensive mistakes in crypto are the same every year:

1. **Sending money to a scam address** (phishing, address poisoning, fake contracts).
2. **Granting an unlimited token approval** to a spender that later drains the wallet.

Both happen *before* the damage, at signing time — which is exactly when nobody is checking. This agent checks.

## What it does

`POST /screen` takes a payment or approval and returns a verdict:

```json
{
  "chain": "bsc",
  "from": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
  "to": "0x000000000000000000000000000000000000dEaD",
  "token": "0x55d398326f99059fF775485246999027B3197955",
  "amount": "10000000000000000000",
  "kind": "transfer"
}
```

Response:

```json
{
  "decision": "ALLOW",
  "risk_score": 0,
  "reasons": [{ "code": "OK", "severity": "info", "weight": 0, "message": "No risk rule triggered..." }],
  "facts": {
    "chain": "bsc", "chain_id": 56,
    "to_is_contract": false, "to_verified": null, "to_age_hours": null,
    "token_symbol": "USDT", "token_decimals": 18,
    "from_balance": "100000000000000000000", "current_allowance": null,
    "spender_known": false, "spender_name": null, "seen_before": false
  },
  "proof_ref": null,
  "screened_at": "2026-11-15T02:11:17.673Z",
  "request_id": "bsc|0x5aae...|..."
}
```

## The rules (deterministic, in order)

| # | Rule | Result | Why |
|---|------|--------|-----|
| 1 | Recipient on the public scam deny-list | **BLOCK** | Known phishing / scam address (ScamSniffer list, 1,500 entries) |
| 2 | Approval spender on the deny-list | **BLOCK** | You would be giving a scammer spending rights |
| 3 | Unlimited approval to an **unknown** spender | **BLOCK** | It could drain the full token balance |
| 4 | Unlimited approval to a **known** spender (e.g. PancakeSwap router) | **WARN** | Legitimate pattern, but still risky — prefer a limited amount |
| 5 | Recipient is an **unverified** contract | **WARN** | Source not verified on the explorer |
| 6 | Recipient contract deployed **< 24h ago** | **WARN** | New contracts are a common scam pattern |
| 7 | Amount is **zero** | **WARN** | Not a real payment; zero-value transfers poison address history |
| 8 | Amount is **dust** (< 0.000001 of the token) | **WARN** | Tiny transfers are the address-poisoning pattern |
| 9 | Amount **exceeds the sender's balance** | **WARN** | The transfer would revert on-chain |
| 10 | Material on-chain data **could not be fetched** | **WARN** | Fail-closed: never call it safe without the facts |

Every triggered rule is listed in `reasons` with a human-readable message, and the `facts` object shows the on-chain evidence behind it. The decision is never a black box. `risk_score` is the sum of the triggered rules' weights (0–100).

## Try it (3 one-click examples)

Open `/demo` in a browser. The three buttons fill in real mainnet cases:

| Example | Expected | Why |
|---|---|---|
| 1. Transfer 10 USDT (BSC) to the burn address | **ALLOW** (score 0) | Plain EOA recipient, normal amount, balance covers it |
| 2. Unlimited USDT approval to PancakeSwap V2 Router | **WARN** (score 35) | `UNLIMITED_APPROVAL_KNOWN_SPENDER` — legitimate router, but unlimited |
| 3. Unlimited USDT approval to an unknown address | **BLOCK** (score 85) | `UNLIMITED_APPROVAL_RISKY` — could drain the full balance |

## Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/screen` | Screen a transfer or approval. Body ≤ 10 KB, JSON. See request format above. `kind` is `"transfer"` or `"approval"`; `spender` + `approval_amount` are required for approvals. `token` is an ERC-20 address or `"native"`. `amount` is a decimal string of integer base units (BigInt — never a float). Chains: `eth` (1), `bsc` (56), `base` (8453). Also accepts signed Proof Gatekeeper arena tasks (see below). |
| `POST` | `/arena/gatekeeper` | Proof Gatekeeper arena tasks (signed). See "Arena (Proof Gatekeeper)". |
| `GET` | `/health` | `{ "status": "ok", "service": "payment-guard", "version": "1.0.0", "time": ... }` |
| `GET` | `/demo` | Interactive demo page (the 3 examples above) |
| `GET` | `/` | Service info + endpoint list |

Errors are plain JSON: `400 INVALID_INPUT` (bad address / amount / chain / unknown field), `400 INVALID_JSON`, `401 BAD_SIGNATURE` (arena task with a bad or missing HMAC signature, or no secret configured), `413 BODY_TOO_LARGE`, `429 RATE_LIMITED` (60/min per IP), `404 NOT_FOUND`.

## Arena (Proof Gatekeeper)

The same worker also plays the Proof Gatekeeper track. The platform
posts a signed task envelope to the registered endpoint (`/screen`),
and the agent answers with one deterministic decision within 60
seconds. Full protocol notes: `../arena/PROTOCOL.md`.

- **HMAC first.** Every task carries an `x-agent-games-signature`
  header (HMAC-SHA256, hex, over the exact raw body). The signature is
  verified before the body is parsed. A bad signature, a missing
  signature, or a missing secret is a 401 — no decision is made.
  The secret comes from the `AGENT_GAMES_HMAC_SECRET` Worker secret
  (set with `wrangler secret put AGENT_GAMES_HMAC_SECRET`). It is
  never committed anywhere. While it is not set, the arena route
  fails closed. (The secret was first stored in the dashboard under
  the name `Agent_games`; the worker also accepts that name as a
  fallback, with the canonical name winning.)
- **Decision.** A fixed checklist over the task fields. Approve only
  when every check passes: proof key matches the registered key *and*
  the registered key matches the value the platform published
  (`0x6b79c6...d77b0`), public balance meets the minimum, the condition
  has not expired, the recipient matches the condition, the amount is
  within the cap, and the proof reference was not already accepted.
  First mismatch wins and names the trap (`VK_SUBSTITUTION`,
  `THRESHOLD_MISMATCH`, `PROOF_REUSED`, `EXPIRED_CONDITION`,
  `RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW`). Any error or uncertainty
  is a REJECT.
- **Idempotency.** Task IDs are idempotency keys: a retried task gets
  the byte-identical response it got the first time.
- **Response.** `{ decision, reason_code, proof_tx }`, signed with
  `x-agent-games-signature` over the raw response body.
- **No proof attached yet.** The decision is correct and complete,
  but no Groth16 proof is generated inside the Worker: proving takes
  about 1.2 s of elliptic-curve CPU (measured locally), which the free
  Worker plan does not allow per request — attempting it would kill
  the response and score a timeout instead of a decision. So the agent
  answers the decision and takes the missing-proof deduction (−2 per
  provable task, no reliability bonus) rather than timing out. The
  proving pipeline itself is verified locally with the tournament's
  own circuit (see "Test results"), and the code is ready for a
  separate proving service.

## How to verify a decision

1. **Recipient check:** `to_is_contract` comes from `eth_getCode`. If the recipient is on the deny-list, look it up in the [ScamSniffer scam-database](https://github.com/scamsniffer/scam-database) (the list is baked into `src/lists.ts`, 1,500 of 4,600 entries, fetched 2026-11-15).
2. **Approval check:** the approval amount is compared to 2²⁵⁵ — anything at or above that is treated as unlimited. The spender is looked up in the known-spender registry (`src/lists.ts`: PancakeSwap, Uniswap, 1inch, 0x).
3. **Contract check:** verification + age come from the Blockscout explorer API (ETH, Base). Canonical tokens (USDT/USDC/WBNB/WETH) are treated as verified by definition.
4. **Amount check:** `amount` is compared to the sender's on-chain balance (`eth_getBalance` / `balanceOf`) using BigInt — no floating point anywhere.

## Test results

- **Unit tests:** 18/18 pass (`npm test`) — every rule has a pass-case and a trigger-case, run against a mock provider (no network).
- **Live tests:** 6/6 pass — real read-only calls to BSC/ETH mainnet (USDT contracts, burn address, a documented phishing contract, all 3 demo cases).
- **Load test:** 50 sequential `/screen` calls against real RPCs — p50 229 ms, **p95 401 ms**, max 1,692 ms. The engine itself is < 2 ms; the rest is public-RPC latency.
- **End-to-end worker test:** the bundled worker (`dist/worker.js`) called directly — `/health`, `/demo`, all 3 demo decisions, and the 400/404 error paths all behave as documented.
- **Arena unit tests:** 21/21 pass (`test/arena.test.ts`) — the decision checklist against all seven trap varieties (valid, VK substitution, unregistered keys, threshold, reuse, expired, recipient, amount, plus boundary cases), and the HMAC checks (correct signature verifies; tampered body, wrong secret, missing secret, missing signature, and malformed signature all rejected).
- **Arena end-to-end test:** 15/15 pass (`test-worker-local.mjs`) — the built worker called directly: health/demo/screen still work, a valid signed task returns APPROVE with a verifiable response signature, a retried task returns the identical body, an amount-overflow trap returns REJECT, and tampered body / wrong secret / missing secret / missing signature all return 401. An arena task posted to the registered endpoint (`/screen`) is answered as an arena task.
- **Groth16 proof (local, snarkjs 0.7.6):** the tournament's own circuit files, verified by hash. A valid approve proof builds in ~1.2 s (cold) / ~300 ms (warm) and `snarkjs groth16 verify` returns OK; the commitment matches `Poseidon(salt, taskId)`. Full trap matrix: for each of the six on-circuit trap varieties, the correct decision builds and verifies and the wrong decision is refused by the circuit (`Assert Failed. Error in template GatekeeperEvaluation_79 line: 102`). For two equal but unregistered keys the circuit accepts the approve proof — which is exactly why the agent checks the registered key against the published value off-circuit. See `../arena/PROTOCOL.md`.

## Limits (honest)

- **BSC contract verification is "unknown".** Etherscan/BscScan V2 APIs require an API key, so for BSC the guard cannot confirm a contract is verified and fails closed to WARN on unknown contracts (canonical tokens excepted). With an explorer API key this becomes a real verification check.
- **The deny-list is a starter set** (1,500 of ~4,600 ScamSniffer entries). Absence from the list proves nothing — the other rules (unlimited approval, unverified/new contract, dust) still apply.
- **No zkVerify proof yet.** Decisions are deterministic and fully auditable (rules + facts), which is the prerequisite for a proof, but no Groth16 proof is attached (`proof_ref: null`). Adding a proof of the screening decision via zkVerify (Kurier) is planned as a follow-up.
- **No price data.** Amount anomalies are judged in token units and against the sender's balance, not in USD — a price feed would sharpen the anomaly rule.

## Run it locally

```bash
npm install
npm test          # unit + live tests (live tests hit public mainnet RPCs, read-only)
npm run build     # esbuild -> dist/worker.js (93 KB, single file)
npx wrangler dev  # local dev server on http://localhost:8787
```

## Deploy

```bash
# Needs a valid Cloudflare API token (Workers:Edit + Account:Read).
CLOUDFLARE_API_TOKEN=<token> npx wrangler deploy
# ...or upload the prebuilt bundle with the connector helper:
# python3 ~/workspace/custom-connectors/custom.cloudflare/bin/cf.py deploy <account_id> payment-guard dist/worker.js
```

Target URL: `https://payment-guard.parcok03.workers.dev` (workers.dev subdomain `parcok03`).

## Files

```
guard/
  src/
    types.ts      shared types (amounts are decimal strings, never floats)
    validate.ts   strict input validation + EIP-55 checksum (js-sha3)
    lists.ts      scam deny-list (1,500) + known spenders + known tokens
    onchain.ts    read-only RPC + Blockscout provider (no key needed)
    engine.ts     deterministic screening engine (10 rules, fail-closed)
    arena.ts      Proof Gatekeeper arena logic (HMAC, decision checklist)
    worker.ts     Cloudflare Worker entry (POST /screen, /arena/gatekeeper, GET /health, /demo, /)
    demo.ts       demo page HTML
  test/
    engine.test.ts  18 unit tests (mock provider)
    live.test.ts    6 live tests (real mainnet, read-only)
    arena.test.ts   21 arena unit tests (decision checklist + HMAC)
  test-worker-local.mjs  15 end-to-end worker tests (built bundle, no network)
  wrangler.toml   worker config
  README.md       this file
```

The arena protocol notes, circuit files, and proving scripts live in
`../arena/` (`PROTOCOL.md`, `circuits/`, `test-proof.cjs`,
`test-trap-matrix.cjs`, `probe-signals.cjs`).

## Status

Built 15 Nov 2026 for the zkVerify Agent Games Wildcard track. See `../STATUS.md` for the deployment status and what is still needed from the user (Cloudflare token + competition registration/submission).
