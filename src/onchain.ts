// Read-only on-chain data provider. Everything here is a READ (eth_call /
// eth_getCode / eth_getBalance / explorer GET). This agent NEVER sends a
// transaction, NEVER asks for a private key, and NEVER signs anything.
//
// Public RPCs (no key) + Blockscout explorer APIs (no key). If a source
// fails or times out, the fact is reported as unknown and the engine
// fails closed to WARN instead of guessing.

import type { ChainName, OnChainFacts, OnChainProvider, ScreenRequest } from "./types.js";
import { KNOWN_TOKENS } from "./lists.js";

export const RPCS: Record<ChainName, string[]> = {
  // Verified live from this environment 2026-11-15 (eth_getCode round-trip).
  // eth.llamarpc.com returns HTTP 525 and cloudflare-eth.com returns a
  // JSON-RPC "Internal error" for eth_getCode, so they are NOT listed.
  eth: ["https://ethereum.publicnode.com", "https://eth.drpc.org", "https://eth-mainnet.public.blastapi.io"],
  bsc: ["https://bsc-dataseed.binance.org", "https://bsc.publicnode.com"],
  base: ["https://mainnet.base.org", "https://base.publicnode.com"],
};

export const BLOCKSCOUT: Record<ChainName, string | null> = {
  eth: "https://eth.blockscout.com/api/v2",
  base: "https://base.blockscout.com/api/v2",
  bsc: null, // BSC has no public Blockscout instance; verification/age stay unknown
};

const FETCH_TIMEOUT_MS = 3000;

async function fetchJson(url: string, init?: RequestInit, timeoutMs = FETCH_TIMEOUT_MS): Promise<unknown> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    if (!res.ok) return null;
    return (await res.json()) as unknown;
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

async function rpcCall(chain: ChainName, method: string, params: unknown[]): Promise<unknown> {
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
  for (const url of RPCS[chain]) {
    const out = (await fetchJson(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    })) as { result?: unknown; error?: unknown } | null;
    if (out && !out.error && out.result !== undefined) return out.result;
  }
  return null;
}

function encodeCall(to: string, data: string): unknown[] {
  return [{ to, data }, "latest"];
}

const BALANCE_OF = "0x70a08231"; // balanceOf(address)
const ALLOWANCE = "0xdd62ed3e"; // allowance(address,address)
const DECIMALS = "0x313ce567"; // decimals()
const SYMBOL = "0x95d89b41"; // symbol()

function padAddress(addr: string): string {
  return "0".repeat(24) + addr.slice(2).toLowerCase();
}

function hexToBigInt(hex: unknown): bigint | null {
  if (typeof hex !== "string" || !/^0x[0-9a-fA-F]+$/.test(hex)) return null;
  try {
    return BigInt(hex);
  } catch {
    return null;
  }
}

function decodeString(hex: unknown): string | null {
  // ABI-encoded string: offset(32) + length(32) + utf8 bytes.
  if (typeof hex !== "string" || !hex.startsWith("0x")) return null;
  const body = hex.slice(2);
  if (body.length < 128) {
    // Some tokens return bytes32 instead of a string.
    try {
      const bytes = Buffer.from(body, "hex");
      const s = bytes.toString("utf8").replace(/\0+$/g, "");
      return s.length > 0 && /^[\x20-\x7E]+$/.test(s) ? s : null;
    } catch {
      return null;
    }
  }
  try {
    const len = Number(BigInt("0x" + body.slice(64, 128)));
    const bytes = Buffer.from(body.slice(128, 128 + len * 2), "hex");
    return bytes.toString("utf8");
  } catch {
    return null;
  }
}

async function getContractInfo(
  chain: ChainName,
  address: string,
): Promise<{ verified: boolean | null; ageHours: number | null }> {
  const base = BLOCKSCOUT[chain];
  if (!base) return { verified: null, ageHours: null };
  const url = `${base}/smart-contracts/${address}`;
  const out = (await fetchJson(url)) as {
    is_verified?: boolean;
    creation_bytecode?: string;
    creation_tx_hash?: string;
    deployed_bytecode?: string;
  } | null;
  if (!out) return { verified: null, ageHours: null };
  const verified = typeof out.is_verified === "boolean" ? out.is_verified : null;
  // Age: Blockscout v2 does not return creation time on this endpoint, so
  // ask for the creation transaction and read its block timestamp.
  let ageHours: number | null = null;
  if (out.creation_tx_hash) {
    const tx = (await fetchJson(`${base}/transactions/${out.creation_tx_hash}`)) as {
      timestamp?: string;
      block?: number;
    } | null;
    if (tx?.timestamp) {
      const ts = Date.parse(tx.timestamp);
      if (!Number.isNaN(ts)) ageHours = Math.max(0, (Date.now() - ts) / 3_600_000);
    }
  }
  return { verified, ageHours };
}

export class RpcProvider implements OnChainProvider {
  async getFacts(req: ScreenRequest): Promise<OnChainFacts> {
    const chain = req.chain as ChainName;
    const to = req.to;
    const from = req.from;
    const isNative = req.token === "native";
    const facts: OnChainFacts = {
      to_is_contract: null,
      to_verified: null,
      to_age_hours: null,
      token_symbol: null,
      token_decimals: null,
      from_balance: null,
      current_allowance: null,
      data_unavailable: false,
    };

    // 1. Is `to` a contract? (eth_getCode — the most reliable single call.)
    const code = await rpcCall(chain, "eth_getCode", [to, "latest"]);
    if (typeof code === "string") {
      facts.to_is_contract = code !== "0x" && code !== "0x0";
    } else {
      facts.data_unavailable = true;
    }

    // 2. Balance of `from` (native or token).
    if (isNative) {
      const bal = await rpcCall(chain, "eth_getBalance", [from, "latest"]);
      const v = hexToBigInt(bal);
      if (v !== null) facts.from_balance = v.toString();
      else facts.data_unavailable = true;
    } else {
      const token = req.token;
      const [bal, dec, sym] = await Promise.all([
        rpcCall(chain, "eth_call", encodeCall(token, BALANCE_OF + padAddress(from))),
        rpcCall(chain, "eth_call", encodeCall(token, DECIMALS)),
        rpcCall(chain, "eth_call", encodeCall(token, SYMBOL)),
      ]);
      const balV = hexToBigInt(bal);
      if (balV !== null) facts.from_balance = balV.toString();
      else facts.data_unavailable = true;
      const decV = hexToBigInt(dec);
      if (decV !== null) facts.token_decimals = Number(decV);
      const symV = decodeString(sym);
      if (symV) facts.token_symbol = symV;
    }

    // 3. Current allowance (approval only).
    if (req.kind === "approval" && req.spender && !isNative) {
      const al = await rpcCall(
        chain,
        "eth_call",
        encodeCall(req.token, ALLOWANCE + padAddress(from) + padAddress(req.spender)),
      );
      const alV = hexToBigInt(al);
      if (alV !== null) facts.current_allowance = alV.toString();
      else facts.data_unavailable = true;
    }

    // 4. Verification + age (only meaningful when `to` is a contract).
    // Canonical well-known tokens are treated as verified: they are the
    // reference deployments, not unknown contracts. This keeps the guard
    // from warning on every USDT/USDC interaction on chains whose explorer
    // needs an API key (BSC).
    if (facts.to_is_contract) {
      if (KNOWN_TOKENS.has(to.toLowerCase())) {
        facts.to_verified = true;
      } else {
        const info = await getContractInfo(chain, to);
        facts.to_verified = info.verified;
        facts.to_age_hours = info.ageHours;
      }
      // If we know it is a contract but could not check verification at all,
      // the engine treats verification as unknown (fail-closed WARN).
    }
    return facts;
  }
}
