// Input validation: strict, fail-closed. Anything malformed is rejected
// with a 400 before the engine ever runs. Amounts use BigInt, never float
// (a float rounding error once cost a real listing its price).

import type { ChainName, ScreenKind, ScreenRequest } from "./types.js";

export const CHAINS: Record<string, { name: ChainName; id: number }> = {
  eth: { name: "eth", id: 1 },
  "1": { name: "eth", id: 1 },
  bsc: { name: "bsc", id: 56 },
  "56": { name: "bsc", id: 56 },
  base: { name: "base", id: 8453 },
  "8453": { name: "base", id: 8453 },
};

const HEX40 = /^0x[0-9a-fA-F]{40}$/;

// EIP-55 checksum via js-sha3 (well-tested keccak-256). My first attempt
// hand-rolled keccak and failed 0/5 EIP-55 vectors, so it was replaced
// with the library instead of debugged in place.
import pkg from "js-sha3";
const keccak256 = (pkg as unknown as { keccak256: (message: string) => string }).keccak256;

export function toChecksumAddress(address: string): string | null {
  if (!HEX40.test(address)) return null;
  const lower = address.slice(2).toLowerCase();
  const hash = keccak256(lower);
  let out = "0x";
  for (let i = 0; i < 40; i++) {
    const ch = lower[i];
    out += parseInt(hash[i], 16) >= 8 ? ch.toUpperCase() : ch;
  }
  return out;
}

export function isValidAddress(address: unknown): address is string {
  return typeof address === "string" && toChecksumAddress(address) !== null;
}

export function parseAmount(raw: unknown): bigint | null {
  if (typeof raw !== "string" || !/^[0-9]+$/.test(raw)) return null;
  try {
    return BigInt(raw);
  } catch {
    return null;
  }
}

export interface ValidatedRequest {
  ok: true;
  req: ScreenRequest;
  chain: { name: ChainName; id: number };
  amount: bigint;
  approvalAmount: bigint | null;
}

export interface ValidationError {
  ok: false;
  error: string;
  field: string;
}

export function validateScreenRequest(body: unknown): ValidatedRequest | ValidationError {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return { ok: false, error: "body must be a JSON object", field: "body" };
  }
  const b = body as Record<string, unknown>;
  const allowed = new Set(["chain", "from", "to", "token", "amount", "kind", "spender", "approval_amount"]);
  for (const key of Object.keys(b)) {
    if (!allowed.has(key)) return { ok: false, error: `unknown field: ${key}`, field: key };
  }
  const chainRaw = typeof b.chain === "string" ? b.chain.toLowerCase() : "";
  const chain = CHAINS[chainRaw];
  if (!chain) return { ok: false, error: "chain must be one of eth, bsc, base (or 1, 56, 8453)", field: "chain" };
  if (!isValidAddress(b.from)) return { ok: false, error: "from must be a valid 0x address", field: "from" };
  if (!isValidAddress(b.to)) return { ok: false, error: "to must be a valid 0x address", field: "to" };
  if (b.token !== "native" && !isValidAddress(b.token)) {
    return { ok: false, error: 'token must be "native" or a valid 0x address', field: "token" };
  }
  const amount = parseAmount(b.amount);
  if (amount === null) return { ok: false, error: "amount must be a decimal string of integer base units", field: "amount" };
  const kind = b.kind as ScreenKind;
  if (kind !== "transfer" && kind !== "approval") {
    return { ok: false, error: 'kind must be "transfer" or "approval"', field: "kind" };
  }
  let spender: string | null = null;
  let approvalAmount: bigint | null = null;
  if (kind === "approval") {
    if (!isValidAddress(b.spender)) return { ok: false, error: "spender is required for kind=approval and must be a valid 0x address", field: "spender" };
    spender = b.spender as string;
    if (b.approval_amount !== undefined && b.approval_amount !== null) {
      approvalAmount = parseAmount(b.approval_amount);
      if (approvalAmount === null) return { ok: false, error: "approval_amount must be a decimal string of integer base units", field: "approval_amount" };
    } else {
      approvalAmount = amount;
    }
  } else if (b.spender !== undefined && b.spender !== null) {
    return { ok: false, error: "spender is only allowed for kind=approval", field: "spender" };
  }
  return {
    ok: true,
    req: {
      chain: chainRaw,
      from: b.from as string,
      to: b.to as string,
      token: b.token as string,
      amount: b.amount as string,
      kind,
      spender,
      approval_amount: approvalAmount === null ? null : approvalAmount.toString(),
    },
    chain,
    amount,
    approvalAmount,
  };
}
