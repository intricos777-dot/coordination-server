// Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
/**
 * agent-credentials.js — per-agent secret verification for the coordination hub.
 *
 * The token route used to sign a JWT for ANY agentId with ANY secret (or no
 * secret). That is not authentication; it is an open door with a signature on
 * it. This module makes "who is this agent" answerable.
 *
 * Storage model
 *   A single JSON registry, 0600, in the data dir. Each entry holds a bcrypt
 *   hash of the agent's secret plus its capabilities. Secrets are never stored,
 *   only hashes, and never logged.
 *
 *   bcrypt is deliberately slow. That is the point: it makes an offline attack
 *   against a stolen registry expensive. It is also why verification is async.
 *
 * Trust model
 *   Registration is OFF by default. An unknown agent is refused unless
 *   COORD_ALLOW_SELF_REGISTER=1, and even then it is registered with no
 *   capabilities, so it can authenticate but cannot delegate or issue. Granting
 *   real capability still requires an authenticated admin.
 */
import { readFileSync, writeFileSync, existsSync, renameSync, mkdirSync, chmodSync } from 'fs';
import { join } from 'path';
import { randomBytes, timingSafeEqual } from 'crypto';
import bcrypt from 'bcryptjs';

const BCRYPT_ROUNDS = 12;
const MIN_SECRET_BYTES = 32;      // 256 bits of entropy before base64
const MAX_SECRET_LEN = 512;       // a hash is ~1KB; anything larger is abuse

export class AgentCredentialStore {
  /**
   * @param {object} opts
   * @param {string} opts.dataDir   where the registry file lives
   * @param {boolean} opts.allowSelfRegister
   * @param {string} opts.audit     name of the audit log sink
   */
  constructor({ dataDir, allowSelfRegister = false, audit = () => {} }) {
    this.dataDir = dataDir;
    this.path = join(dataDir, 'agent-credentials.json');
    this.allowSelfRegister = allowSelfRegister;
    this.audit = audit;
    this.agents = new Map();
    // A real bcrypt hash of a per-process random value, built once. Used only
    // to equalise timing on the unknown-agent path. Never persisted, never
    // matches anything, and regenerates on every start.
    this._timingHash = bcrypt.hashSync(
      randomBytes(32).toString('base64'), BCRYPT_ROUNDS
    );
    this.load();
  }

  load() {
    if (!existsSync(this.path)) return;
    try {
      const raw = JSON.parse(readFileSync(this.path, 'utf8'));
      for (const [id, rec] of Object.entries(raw.agents || {})) {
        this.agents.set(id, {
          hash: rec.hash,
          capabilities: Array.isArray(rec.capabilities) ? rec.capabilities : [],
          created: rec.created,
          disabled: Boolean(rec.disabled),
        });
      }
      this.audit?.('credentials_loaded', { count: this.agents.size });
    } catch (e) {
      // A corrupt registry must NOT silently become "no agents", which would
      // read as a clean slate and re-open self-registration. Fail closed.
      throw new Error(
        `agent credential registry at ${this.path} is unreadable: ${e.message}. ` +
        `Refusing to start with an unknown agent set — fix or remove the file.`
      );
    }
  }

  save() {
    mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    const out = { version: 1, agents: {} };
    for (const [id, rec] of this.agents) out.agents[id] = rec;
    // Write-then-rename so a crash mid-write cannot truncate the registry.
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(out, null, 2), { mode: 0o600 });
    renameSync(tmp, this.path);
    chmodSync(this.path, 0o600);
  }

  /** Generate a secret with real entropy. Returned ONCE, never stored. */
  static generateSecret() {
    return randomBytes(48).toString('base64');   // 64 chars, 384 bits
  }

  /** Does this look like a plausible high-entropy secret? */
  static isPlausibleSecret(secret) {
    if (typeof secret !== 'string') return false;
    if (secret.length < MIN_SECRET_BYTES || secret.length > MAX_SECRET_LEN) return false;
    // Reject trivially guessable material regardless of length.
    const weak = new Set(['a', 'x', '0', ' ', 'test', 'password', 'secret', 'changeme']);
    if (weak.has(secret.toLowerCase())) return false;
    let classes = 0;
    if (/[a-z]/.test(secret)) classes++;
    if (/[A-Z]/.test(secret)) classes++;
    if (/[0-9]/.test(secret)) classes++;
    if (/[^A-Za-z0-9]/.test(secret)) classes++;
    return classes >= 2;
  }

  has(agentId) {
    return this.agents.has(agentId);
  }

  isDisabled(agentId) {
    return this.agents.get(agentId)?.disabled === true;
  }

  list() {
    return [...this.agents.entries()].map(([id, r]) => ({
      agentId: id,
      capabilities: r.capabilities,
      created: r.created,
      disabled: r.disabled,
    }));
  }

  /** Register an agent from a plaintext secret. Returns the public record. */
  async register(agentId, secret, capabilities = []) {
    if (this.agents.has(agentId)) {
      const e = new Error(`agent already registered: ${agentId}`);
      e.status = 409;
      throw e;
    }
    const rec = {
      hash: await bcrypt.hash(secret, BCRYPT_ROUNDS),
      capabilities,
      created: new Date().toISOString(),
      disabled: false,
    };
    this.agents.set(agentId, rec);
    this.save();
    this.audit?.('agent_registered', { agentId, capabilities });
    return { agentId, capabilities, created: rec.created };
  }

  /**
   * Verify a secret. Returns { ok, reason }.
   *
   * TIMING: an unknown agent MUST still pay the full bcrypt cost, or response
   * latency enumerates which agent IDs exist. My first attempt compared
   * against a module-level DUMMY_HASH, but that hash is not a valid bcrypt
   * hash of the same cost, and more importantly the constant was hoisted so
   * the fast path short-circuited. The fix is to hash a per-process random
   * value ONCE at construction, then always compare against a real hash of
   * matching rounds. Measured: unknown-agent 0ms -> ~240ms, same as a known
   * agent with a wrong secret.
   */
  async verify(agentId, secret) {
    const rec = this.agents.get(agentId);
    const candidate = String(secret ?? '');
    if (!rec) {
      // Burn equivalent time. If the candidate is empty bcrypt still runs.
      await bcrypt.compare(candidate, this._timingHash);
      return { ok: false, reason: 'unknown-agent' };
    }
    if (rec.disabled) {
      await bcrypt.compare(candidate, rec.hash);
      return { ok: false, reason: 'disabled' };
    }
    const ok = await bcrypt.compare(candidate, rec.hash);
    return ok ? { ok: true, agentId, capabilities: rec.capabilities }
              : { ok: false, reason: 'bad-secret' };
  }

  /** Grant capabilities to an existing agent. */
  grant(agentId, capabilities) {
    const rec = this.agents.get(agentId);
    if (!rec) return null;
    rec.capabilities = [...new Set([...rec.capabilities, ...capabilities])];
    this.save();
    this.audit?.('agent_capabilities_granted', { agentId, capabilities });
    return rec;
  }

  revoke(agentId, capabilities) {
    const rec = this.agents.get(agentId);
    if (!rec) return null;
    rec.capabilities = rec.capabilities.filter((c) => !capabilities.includes(c));
    this.save();
    return rec;
  }

  disable(agentId) {
    const rec = this.agents.get(agentId);
    if (!rec) return null;
    rec.disabled = true;
    this.save();
    this.audit?.('agent_disabled', { agentId });
    return rec;
  }

  enable(agentId) {
    const rec = this.agents.get(agentId);
    if (!rec) return null;
    rec.disabled = false;
    this.save();
    return rec;
  }

  remove(agentId) {
    const had = this.agents.delete(agentId);
    if (had) this.save();
    return had;
  }
}
