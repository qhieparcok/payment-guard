// Shared types for the Payment & Wallet Security Guard.
// Plain data, no logic here. All amounts are decimal strings of integer
// base units (never floats) so BigInt math stays exact.

export type ChainName = "eth" | "bsc" | "base";
export type ScreenKind = "transfer" | "approval";
export type Decision = "ALLOW" | "WARN" | "BLOCK";

export type ReasonCode =
  | "OK"
  | "SCAM_ADDRESS"
  | "RISKY_SPENDER"
  | "UNLIMITED_APPROVAL_RISKY"
  | "UNLIMITED_APPROVAL_KNOWN_SPENDER"
  | "UNVERIFIED_CONTRACT"
  | "NEW_CONTRACT"
  | "ZERO_AMOUNT"
  | "DUST_AMOUNT"
  | "INSUFFICIENT_BALANCE"
  | "DATA_UNAVAILABLE";

export interface Reason {
  code: ReasonCode;
  severity: "block" | "warn" | "info";
  weight: number;
  message: string;
}

export interface ScreenRequest {
  chain: string; // "eth" | "bsc" | "base" or chain id "1" | "56" | "8453"
  from: string; // sender address (checksummed or lowercase hex)
  to: string; // recipient address
  token: string; // ERC-20 contract address, or "native"
  amount: string; // integer base units, decimal string, >= 0
  kind: ScreenKind; // "transfer" | "approval"
  spender?: string | null; // required when kind === "approval"
  approval_amount?: string | null; // amount being approved (defaults to amount)
}

export interface Facts {
  chain: ChainName;
  chain_id: number;
  to_is_contract: boolean | null;
  to_verified: boolean | null; // null = could not determine
  to_age_hours: number | null; // null = unknown
  token_symbol: string | null;
  token_decimals: number | null;
  from_balance: string | null; // base units, decimal string
  current_allowance: string | null; // base units, only for approval
  spender_known: boolean | null;
  spender_name: string | null;
  seen_before: boolean;
}

export interface ScreenResult {
  decision: Decision;
  risk_score: number; // 0..100
  reasons: Reason[];
  facts: Facts;
  proof_ref: string | null; // zkVerify proof reference (optional, null for now)
  screened_at: string; // ISO timestamp
  request_id: string; // fingerprint of the screened request
}

export interface OnChainFacts {
  to_is_contract: boolean | null;
  to_verified: boolean | null;
  to_age_hours: number | null;
  token_symbol: string | null;
  token_decimals: number | null;
  from_balance: string | null;
  current_allowance: string | null;
  data_unavailable: boolean; // true when a material lookup failed
}

// A data provider answers read-only on-chain questions. The engine never
// talks to the network directly, so tests can inject a mock.
export interface OnChainProvider {
  getFacts(req: ScreenRequest): Promise<OnChainFacts>;
}
