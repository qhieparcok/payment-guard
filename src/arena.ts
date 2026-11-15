// Proof Gatekeeper arena handler.
// Receives a signed task envelope, decides APPROVE or REJECT, and answers
// within the 60-second window. The platform signs every task with the
// agent's HMAC secret; a bad signature or a missing secret means the task
// is rejected before any other work happens. Fail closed, always.
//
// The decision is a fixed checklist over the task fields. Approve only
// when every check passes. One mismatch is a rejection, and the reason
// code names the trap that was caught.

export const ARENA_VERSION = "gatekeeper-v1";

// The verification-key hash the platform published for this circuit.
// A proof whose keys are equal but not this value still verifies
// cryptographically — the circuit only checks the two keys match each
// other. So the agent checks both keys against this value itself.
export const REGISTERED_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

export const GATEKEEPER_TASK_TYPE = "agent-games.proof-gatekeeper.v1";

export type GatekeeperDecision = "APPROVE" | "REJECT";

export type GatekeeperReason =
  | "VALID_CONDITION"
  | "VK_SUBSTITUTION"
  | "THRESHOLD_MISMATCH"
  | "PROOF_REUSED"
  | "EXPIRED_CONDITION"
  | "RECIPIENT_MISMATCH"
  | "AMOUNT_OVERFLOW";

export interface GatekeeperInput {
  registered_vk: string;
  proof_vk: string;
  minimum: string;
  public_balance: string;
  expiry_block: number;
  current_block: number;
  recipient: string;
  condition_recipient: string;
  amount: string;
  max_transfer: string;
  proof_tx: string;
}

export interface GatekeeperTask {
  type: string;
  task_id: string;
  mode?: string;
  issued_at?: string;
  deadline_at?: string;
  input: GatekeeperInput;
}

export interface GatekeeperVerdict {
  decision: GatekeeperDecision;
  reason_code: GatekeeperReason;
  proof_tx: string;
}

// --- Hex normalization --------------------------------------------------

// Canonical form of a hex value (address, vk hash, proof reference):
// strip an optional 0x prefix and lowercase. The platform may send
// the same value checksummed, lowercased, with or without the prefix;
// without normalizing, the same value can look different and a valid
// task is wrongly rejected — or a reused proof is missed, which is
// worse (a wrong APPROVE costs more than a wrong REJECT).
export function normalizeHex(value: string | undefined): string | null {
  if (typeof value !== "string") return null;
  const t = value.trim().toLowerCase();
  if (!t) return null;
  return t.startsWith("0x") ? t.slice(2) : t;
}

// Canonical key for a proof reference in the seen-set (and in KV).
// Same normalization as hexEqual, so a proof submitted once
// checksummed and once lowercased still counts as the same proof.
export function normalizeProofTx(value: string | undefined): string | null {
  return normalizeHex(value);
}

// --- HMAC ---------------------------------------------------------------

// Turn the configured secret into key bytes. The platform issues a
// 32-byte random secret; it is usually shown as 64 hex characters.
// Accept that form first, then base64, then fall back to the raw text.
export function secretToKey(secret: string): Uint8Array {
  const trimmed = secret.trim();
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
  try {
    const decoded = Uint8Array.from(atob(trimmed), (c) => c.charCodeAt(0));
    if (decoded.length === 32) return decoded;
  } catch {
    // not base64; fall through to raw text
  }
  return new TextEncoder().encode(trimmed);
}

async function hmacBytes(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, data as BufferSource);
  return new Uint8Array(sig);
}

async function hmacHex(key: Uint8Array, data: Uint8Array): Promise<string> {
  const sig = await hmacBytes(key, data);
  return Array.from(sig)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Compare two byte arrays without short-circuiting, so the timing does
// not leak how many leading bytes matched.
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

// Compare two hex digests without short-circuiting, so the timing does
// not leak how many leading characters matched.
function digestsEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// Candidate HMAC keys for one configured secret. The platform issues
// a 32-byte secret, usually shown as 64 hex characters, but its own
// signing code may use the hex-decoded bytes, the raw text, or the
// base64-decoded bytes as the key — that choice is not documented.
// Try them in that order; the first one that verifies wins. Every
// candidate still needs the real secret, so accepting several
// derivations does not weaken the check.
export function candidateKeys(secret: string): Uint8Array[] {
  const trimmed = secret.trim();
  const keys: Uint8Array[] = [];
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
    }
    keys.push(bytes);
  } else {
    try {
      const decoded = Uint8Array.from(atob(trimmed), (c) => c.charCodeAt(0));
      if (decoded.length === 32) keys.push(decoded);
    } catch {
      // not base64; fall through to the raw text
    }
  }
  keys.push(new TextEncoder().encode(trimmed));
  return keys;
}

// Parse a presented signature into 32 bytes. Accepts lowercase or
// uppercase hex (64 chars, optionally prefixed with "sha256=") and
// base64 (standard or URL-safe, with or without padding).
function parseSignature(presented: string): Uint8Array | null {
  const p = presented.trim().replace(/^sha256=/i, "");
  if (/^[0-9a-fA-F]{64}$/.test(p)) {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(p.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
  try {
    const normalized = p.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    const decoded = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
    if (decoded.length === 32) return decoded;
  } catch {
    // not base64
  }
  return null;
}

// Canonical form of a JSON body: object keys sorted recursively,
// compact separators. Some signers canonicalise before signing; try
// it when the raw bytes do not verify. Returns null when the body is
// not JSON or its canonical form is byte-identical to the raw body.
function canonicalJsonBytes(rawBody: Uint8Array): Uint8Array | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(rawBody));
  } catch {
    return null;
  }
  const canon = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(canon);
    if (v !== null && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(v as Record<string, unknown>).sort()) {
        out[k] = canon((v as Record<string, unknown>)[k]);
      }
      return out;
    }
    return v;
  };
  const bytes = new TextEncoder().encode(JSON.stringify(canon(parsed)));
  if (bytes.length === rawBody.length && bytes.every((b, i) => b === rawBody[i])) return null;
  return bytes;
}

// Verify the platform's signature over the request. Returns the key
// bytes that verified (so the response can be signed with the same
// derivation), or null when there is no signature, no secret, or no
// match. Tries each key derivation against the raw body first, then
// against the canonical JSON form, and accepts hex or base64
// signature encodings.
export async function verifyTaskSignature(
  rawBody: Uint8Array,
  signatureHeader: string | null,
  secret: string | undefined
): Promise<Uint8Array | null> {
  if (!signatureHeader || !secret) return null;
  const presented = parseSignature(signatureHeader);
  if (!presented) return null;
  const bodies: Uint8Array[] = [rawBody];
  const canon = canonicalJsonBytes(rawBody);
  if (canon) bodies.push(canon);
  for (const key of candidateKeys(secret)) {
    for (const body of bodies) {
      const expected = await hmacBytes(key, body);
      if (bytesEqual(presented, expected)) return key;
    }
  }
  return null;
}

// Sign a response body with an already-resolved key (the one that
// verified the incoming request), so the platform can verify the
// response with the same derivation it used to sign the task.
export async function signResponseBodyWithKey(
  rawBody: Uint8Array,
  key: Uint8Array
): Promise<string> {
  return hmacHex(key, rawBody);
}

// Sign a response body with the same secret, for the
// x-agent-games-signature response header.
export async function signResponseBody(
  rawBody: Uint8Array,
  secret: string
): Promise<string> {
  return hmacHex(secretToKey(secret), rawBody);
}

// --- Decision ------------------------------------------------------------

// Compare two hex values (addresses, vk hashes) case-insensitively
// and independent of the 0x prefix. A missing or malformed value
// never counts as a match.
function hexEqual(a: string | undefined, b: string | undefined): boolean {
  const na = normalizeHex(a);
  const nb = normalizeHex(b);
  if (na === null || nb === null) return false;
  return na === nb;
}

function toBigInt(value: string | number | undefined): bigint | null {
  if (value === undefined || value === null) return null;
  try {
    if (typeof value === "number") {
      if (!Number.isInteger(value)) return null;
      return BigInt(value);
    }
    const s = String(value).trim();
    if (!/^-?\d+$/.test(s) && !/^0x[0-9a-fA-F]+$/.test(s)) return null;
    return BigInt(s);
  } catch {
    return null;
  }
}

export interface DecisionContext {
  // Proof references the agent has already accepted (approved).
  // A proof that was only ever rejected is not "used" — the platform's
  // reuse trap is about proofs that were accepted before.
  seenProofTx: Set<string>;
  // Called when the agent approves, so the proof reference is recorded.
  recordApproval: (proofTx: string) => void;
}

// Evaluate a task envelope. First mismatch wins, so the reason code
// names the trap the agent actually caught. Returns the verdict; the
// caller records the approval when the decision is APPROVE.
export function decideTask(
  task: GatekeeperTask,
  ctx: DecisionContext
): GatekeeperVerdict {
  const input = task.input ?? ({} as GatekeeperInput);
  const proofTx = typeof input.proof_tx === "string" ? input.proof_tx : "";
  // The seen-set is keyed on the NORMALIZED reference, so the same
  // proof submitted once checksummed and once lowercased is still
  // caught as a reuse. The verdict echoes the raw reference, as sent.
  const proofTxKey = normalizeProofTx(proofTx) ?? "";

  const reject = (reason_code: GatekeeperReason): GatekeeperVerdict => ({
    decision: "REJECT",
    reason_code,
    proof_tx: proofTx,
  });

  // 1. Proof reuse. A proof reference that was already accepted in an
  // earlier task does not gain re-entry by being submitted again.
  if (proofTxKey && ctx.seenProofTx.has(proofTxKey)) {
    return reject("PROOF_REUSED");
  }

  // 2. Verification-key substitution. The proof's key must match the
  // key the condition registered, and that key must be the one the
  // platform published. The circuit only checks the two keys match
  // each other, so both comparisons happen here, outside the proof.
  if (!hexEqual(input.proof_vk, input.registered_vk)) {
    return reject("VK_SUBSTITUTION");
  }
  if (!hexEqual(input.registered_vk, REGISTERED_VK_HASH)) {
    return reject("VK_SUBSTITUTION");
  }

  // 3. Threshold. The public balance disclosed in the proof must meet
  // or exceed the condition's required minimum.
  const minimum = toBigInt(input.minimum);
  const balance = toBigInt(input.public_balance);
  if (minimum === null || balance === null || balance < minimum) {
    return reject("THRESHOLD_MISMATCH");
  }

  // 4. Expiry. The condition's block-height expiry must not have
  // passed. At the expiry block itself the window is closed.
  const expiry = toBigInt(input.expiry_block);
  const current = toBigInt(input.current_block);
  if (expiry === null || current === null || current >= expiry) {
    return reject("EXPIRED_CONDITION");
  }

  // 5. Recipient. The address in the proof must match the address on
  // the payment condition, or the money goes to the wrong party.
  if (!hexEqual(input.recipient, input.condition_recipient)) {
    return reject("RECIPIENT_MISMATCH");
  }

  // 6. Amount. The requested payment must not exceed the condition's
  // single-transfer cap.
  const amount = toBigInt(input.amount);
  const cap = toBigInt(input.max_transfer);
  if (amount === null || cap === null || amount > cap) {
    return reject("AMOUNT_OVERFLOW");
  }

  // Every check passed. Record the approval so this proof reference
  // is caught if it is ever submitted again. The normalized key is
  // recorded, so the same proof in a different casing is still caught.
  if (proofTxKey) ctx.recordApproval(proofTxKey);
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", proof_tx: proofTx };
}

// Minimal shape for a task that is not a gatekeeper envelope, or whose
// fields are missing. The agent cannot verify such a task, so it
// rejects rather than guessing. The reason code is the closest trap.
export function isGatekeeperTask(body: unknown): body is GatekeeperTask {
  if (typeof body !== "object" || body === null) return false;
  const t = body as Record<string, unknown>;
  return (
    t.type === GATEKEEPER_TASK_TYPE &&
    typeof t.task_id === "string" &&
    typeof t.input === "object" &&
    t.input !== null
  );
}
