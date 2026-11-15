// Screening engine: pure, deterministic, stateless (except the small
// seen-set). Rules run in order; the first BLOCK/WARN that fires decides
// the tone, but ALL triggered reasons are reported so the decision is
// auditable, never a black box. Fail-closed: when material on-chain data
// cannot be fetched, the answer is WARN, never ALLOW.

import type {
  Facts,
  OnChainProvider,
  Reason,
  ReasonCode,
  ScreenRequest,
  ScreenResult,
} from "./types.js";
import { isScamAddress, knownSpender } from "./lists.js";

// 2^256 - 1 (the usual "unlimited" approval) and 2^255 (anything this big
// is effectively unlimited for a human).
const UINT256_MAX = (1n << 256n) - 1n;
const UNLIMITED_FLOOR = 1n << 255n;
const NEW_CONTRACT_HOURS = 24;

function reason(code: ReasonCode, severity: "block" | "warn" | "info", weight: number, message: string): Reason {
  return { code, severity, weight, message };
}

function fingerprint(req: ScreenRequest): string {
  return [
    req.chain,
    req.from.toLowerCase(),
    req.to.toLowerCase(),
    req.token.toLowerCase(),
    req.amount,
    req.kind,
    (req.spender ?? "").toLowerCase(),
    req.approval_amount ?? "",
  ].join("|");
}

export class ScreeningEngine {
  private seen = new Map<string, number>();
  private readonly seenCap: number;

  constructor(seenCap = 10_000) {
    this.seenCap = seenCap;
  }

  private markSeen(fp: string): boolean {
    const seenBefore = this.seen.has(fp);
    if (!seenBefore) {
      if (this.seen.size >= this.seenCap) {
        const oldest = this.seen.keys().next().value;
        if (oldest !== undefined) this.seen.delete(oldest);
      }
      this.seen.set(fp, Date.now());
    }
    return seenBefore;
  }

  async screen(req: ScreenRequest, provider: OnChainProvider): Promise<ScreenResult> {
    const amount = BigInt(req.amount);
    const approvalAmount = req.approval_amount !== null && req.approval_amount !== undefined
      ? BigInt(req.approval_amount)
      : null;
    const facts = await provider.getFacts(req);
    const reasons: Reason[] = [];

    const toLower = req.to.toLowerCase();
    const spenderLower = req.spender ? req.spender.toLowerCase() : null;
    const spenderName = spenderLower ? knownSpender(spenderLower) : null;

    // 1. Recipient on the scam deny-list -> BLOCK.
    if (isScamAddress(toLower)) {
      reasons.push(
        reason("SCAM_ADDRESS", "block", 100, "Recipient is on the public scam deny-list (ScamSniffer). Do not send."),
      );
    }

    // 2. Approval spender on the deny-list -> BLOCK.
    if (req.kind === "approval" && spenderLower && isScamAddress(spenderLower)) {
      reasons.push(
        reason("RISKY_SPENDER", "block", 90, "Spender is on the public scam deny-list. Do not approve."),
      );
    }

    // 3/4. Unlimited approval: BLOCK to an unknown spender, WARN to a known one.
    if (req.kind === "approval" && approvalAmount !== null) {
      const unlimited = approvalAmount >= UNLIMITED_FLOOR || approvalAmount === UINT256_MAX;
      if (unlimited) {
        if (spenderName) {
          reasons.push(
            reason(
              "UNLIMITED_APPROVAL_KNOWN_SPENDER",
              "warn",
              35,
              `Unlimited approval to a known spender (${spenderName}). It can move all of this token later; prefer a limited amount.`,
            ),
          );
        } else {
          reasons.push(
            reason(
              "UNLIMITED_APPROVAL_RISKY",
              "block",
              85,
              "Unlimited approval to an unknown spender. It could drain the full token balance.",
            ),
          );
        }
      }
    }

    // 5/6. Recipient contract: unverified -> WARN; freshly deployed -> WARN.
    if (facts.to_is_contract === true) {
      if (facts.to_verified === false) {
        reasons.push(
          reason("UNVERIFIED_CONTRACT", "warn", 30, "Recipient is a contract whose source is not verified on the explorer."),
        );
      }
      if (facts.to_age_hours !== null && facts.to_age_hours < NEW_CONTRACT_HOURS) {
        reasons.push(
          reason(
            "NEW_CONTRACT",
            "warn",
            25,
            `Recipient contract was deployed less than ${NEW_CONTRACT_HOURS}h ago (${facts.to_age_hours.toFixed(1)}h). New contracts are a common scam pattern.`,
          ),
        );
      }
    }

    // 7. Zero amount -> WARN (a zero transfer is never a real payment).
    if (amount === 0n) {
      reasons.push(reason("ZERO_AMOUNT", "warn", 15, "Amount is zero. This is not a real payment; zero-value transfers are a poisoning pattern."));
    }

    // 8. Dust amount -> WARN (tiny transfers are the address-poisoning pattern).
    if (amount > 0n) {
      const dustFloor = facts.token_decimals !== null && facts.token_decimals >= 6
        ? 10n ** BigInt(facts.token_decimals - 6)
        : 1000n;
      if (amount < dustFloor) {
        reasons.push(
          reason("DUST_AMOUNT", "warn", 15, "Amount is dust (below 0.000001 of the token). Tiny transfers are used to poison address history."),
        );
      }
    }

    // 9. Amount exceeds the sender's balance -> WARN (the transfer would revert).
    if (facts.from_balance !== null) {
      try {
        if (amount > BigInt(facts.from_balance)) {
          reasons.push(
            reason("INSUFFICIENT_BALANCE", "warn", 20, "Amount exceeds the sender's on-chain balance; the transfer would fail."),
          );
        }
      } catch {
        // from_balance was not a clean integer; ignore rather than crash.
      }
    }

    // 10. Fail-closed: material on-chain data could not be fetched, or a
    // contract's verification status could not be determined at all.
    const verificationUnknown = facts.to_is_contract === true && facts.to_verified === null;
    if (facts.data_unavailable || verificationUnknown) {
      reasons.push(
        reason(
          "DATA_UNAVAILABLE",
          "warn",
          25,
          verificationUnknown
            ? "Could not determine whether the recipient contract is verified (explorer unavailable for this chain). Treating as unverified."
            : "Some on-chain data could not be fetched. Refusing to call this safe without the facts.",
        ),
      );
    }

    // Decision + score.
    const hasBlock = reasons.some((r) => r.severity === "block");
    const hasWarn = reasons.some((r) => r.severity === "warn");
    const decision = hasBlock ? "BLOCK" : hasWarn ? "WARN" : "ALLOW";
    const riskScore = Math.min(
      100,
      reasons.reduce((sum, r) => sum + r.weight, 0),
    );
    if (decision === "ALLOW") {
      reasons.push(reason("OK", "info", 0, "No risk rule triggered. Recipient, amount and spender all check out."));
    }

    const fullFacts: Facts = {
      chain: req.chain as Facts["chain"],
      chain_id: req.chain === "eth" || req.chain === "1" ? 1 : req.chain === "bsc" || req.chain === "56" ? 56 : 8453,
      to_is_contract: facts.to_is_contract,
      to_verified: facts.to_verified,
      to_age_hours: facts.to_age_hours,
      token_symbol: facts.token_symbol,
      token_decimals: facts.token_decimals,
      from_balance: facts.from_balance,
      current_allowance: facts.current_allowance,
      spender_known: spenderName !== null,
      spender_name: spenderName,
      seen_before: this.markSeen(fingerprint(req)),
    };

    return {
      decision,
      risk_score: decision === "ALLOW" ? 0 : riskScore,
      reasons,
      facts: fullFacts,
      proof_ref: null,
      screened_at: new Date().toISOString(),
      request_id: fingerprint(req).slice(0, 64),
    };
  }
}
