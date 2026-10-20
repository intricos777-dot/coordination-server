// Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
/**
 * OCAP (Object Capability) System for Secure Agent Communication
 * 
 * Based on Macaroons: capability tokens with caveats for attenuation
 * Each capability = (identifier, key, caveats[], signature)
 * Caveats are predicates that must be satisfied for authorization
 */

import { createHmac, timingSafeEqual, randomBytes } from 'crypto';
import { createHash } from 'crypto';

// ─── Constants ──────────────────────────────────────────────────────
const ALGORITHM = 'sha256';
const VERSION = 'ocap-v1';
const DEFAULT_TTL = 3600000; // 1 hour
const MAX_CAVEATS = 20;
const MAX_DELEGATION_DEPTH = 10;

// ─── Types ──────────────────────────────────────────────────────────

/**
 * @typedef {Object} Caveat
 * @property {string} type - Caveat type: 'time', 'ip', 'agent', 'resource', 'action', 'delegation', 'custom'
 * @property {Object} condition - Condition parameters
 * @property {string} [description] - Human-readable description
 */

/**
 * @typedef {Object} CapabilityToken
 * @property {string} identifier - Unique capability ID
 * @property {string} version - Token version
 * @property {string} location - Issuer location/hint
 * @property {number} issuedAt - Unix timestamp (ms)
 * @property {number} expiresAt - Unix timestamp (ms)
 * @property {Caveat[]} caveats - List of caveats
 * @property {string} signature - HMAC signature
 * @property {number} delegationDepth - Current delegation depth
 * @property {string} parentId - Parent capability ID (if delegated)
 */

// ─── Core Capability Class ──────────────────────────────────────────

export class Capability {
  /**
   * @param {Object} opts
   * @param {string} opts.identifier - Unique capability identifier
   * @param {string} opts.key - Root signing key (base64)
   * @param {string} [opts.location] - Issuer location hint
   * @param {number} [opts.ttl] - Time to live in ms
   * @param {Caveat[]} [opts.caveats] - Initial caveats
   * @param {number} [opts.delegationDepth=0] - Delegation depth
   * @param {string} [opts.parentId] - Parent capability ID
   */
  constructor({ identifier, key, location, ttl = DEFAULT_TTL, caveats = [], delegationDepth = 0, parentId }) {
    if (!identifier || !key) {
      throw new Error('Capability requires identifier and key');
    }
    if (delegationDepth > MAX_DELEGATION_DEPTH) {
      throw new Error(`Max delegation depth exceeded: ${MAX_DELEGATION_DEPTH}`);
    }

    this.identifier = identifier;
    this.key = Buffer.from(key, 'base64');
    this.location = location || '';
    this.issuedAt = Date.now();
    this.expiresAt = this.issuedAt + ttl;
    this.caveats = [...caveats];
    this.delegationDepth = delegationDepth;
    this.parentId = parentId;
    this.signature = this._sign();
  }

  // ─── Caveat Builders ──────────────────────────────────────────────

  /**
   * Add time-based caveat (must be before expiry)
   * @param {number} expiresAt - Unix timestamp (ms) when capability expires
   */
  addTimeCaveat(expiresAt) {
    this._addCaveat({
      type: 'time',
      condition: { before: expiresAt },
      description: `Valid until ${new Date(expiresAt).toISOString()}`
    });
    return this;
  }

  /**
   * Add IP address restriction caveat
   * @param {string|string[]} ips - Allowed IP addresses or CIDR ranges
   */
  addIPCaveat(ips) {
    const ipList = Array.isArray(ips) ? ips : [ips];
    this._addCaveat({
      type: 'ip',
      condition: { allowed: ipList },
      description: `Restricted to IPs: ${ipList.join(', ')}`
    });
    return this;
  }

  /**
   * Add agent ID restriction caveat
   * @param {string|string[]} agentIds - Allowed agent IDs
   */
  addAgentCaveat(agentIds) {
    const idList = Array.isArray(agentIds) ? agentIds : [agentIds];
    this._addCaveat({
      type: 'agent',
      condition: { allowed: idList },
      description: `Restricted to agents: ${idList.join(', ')}`
    });
    return this;
  }

  /**
   * Add resource access caveat
   * @param {string} resource - Resource pattern (e.g., 'session:*', 'agent:lia-*')
   * @param {string[]} actions - Allowed actions (e.g., ['read', 'write', 'invoke'])
   */
  addResourceCaveat(resource, actions = ['*']) {
    this._addCaveat({
      type: 'resource',
      condition: { resource, actions },
      description: `Access to ${resource} for actions: ${actions.join(', ')}`
    });
    return this;
  }

  /**
   * Add action restriction caveat
   * @param {string[]} actions - Allowed actions
   */
  addActionCaveat(actions) {
    this._addCaveat({
      type: 'action',
      condition: { allowed: actions },
      description: `Allowed actions: ${actions.join(', ')}`
    });
    return this;
  }

  /**
   * Add delegation depth limit caveat
   * @param {number} maxDepth - Maximum further delegation depth
   */
  addDelegationCaveat(maxDepth) {
    this._addCaveat({
      type: 'delegation',
      condition: { maxDepth },
      description: `Max further delegation depth: ${maxDepth}`
    });
    return this;
  }

  /**
   * Add custom predicate caveat
   * @param {string} predicate - Predicate name
   * @param {Object} params - Predicate parameters
   * @param {string} description - Human description
   */
  addCustomCaveat(predicate, params, description) {
    this._addCaveat({
      type: 'custom',
      condition: { predicate, params },
      description
    });
    return this;
  }

  /**
   * Add attenuation caveat (narrows scope)
   * @param {Function} attenuator - Function that returns new caveats
   */
  attenuate(attenuator) {
    const newCaveats = attenuator(this.caveats);
    if (!Array.isArray(newCaveats)) {
      throw new Error('Attenuator must return array of caveats');
    }
    this.caveats.push(...newCaveats);
    this.signature = this._sign();
    return this;
  }

  // ─── Delegation ───────────────────────────────────────────────────

  /**
   * Delegate a new capability with additional caveats
   * @param {Object} opts - Delegation options
   * @param {string} opts.identifier - New capability identifier
   * @param {Caveat[]} [opts.caveats] - Additional caveats
   * @param {number} [opts.ttl] - TTL for delegated capability
   * @returns {Capability} New delegated capability
   */
  delegate({ identifier, caveats = [], ttl }) {
    // Check delegation caveat
    const delegationCaveat = this.caveats.find(c => c.type === 'delegation');
    if (delegationCaveat && this.delegationDepth >= delegationCaveat.condition.maxDepth) {
      throw new Error('Delegation depth limit reached');
    }

    const delegated = new Capability({
      identifier,
      key: this.key.toString('base64'),
      location: this.location,
      ttl: ttl || (this.expiresAt - Date.now()),
      caveats: [...this.caveats, ...caveats],
      delegationDepth: this.delegationDepth + 1,
      parentId: this.identifier
    });

    return delegated;
  }

  // ─── Serialization ────────────────────────────────────────────────

  /**
   * Serialize to compact string format
   * @returns {string} Base64-encoded capability token
   */
  serialize() {
    const payload = {
      v: VERSION,
      id: this.identifier,
      loc: this.location,
      iat: this.issuedAt,
      exp: this.expiresAt,
      cav: this.caveats,
      dep: this.delegationDepth,
      pid: this.parentId,
      sig: this.signature
    };
    return Buffer.from(JSON.stringify(payload)).toString('base64url');
  }

  /**
   * Deserialize from string
   * @param {string} token - Base64-encoded capability token
   * @param {string} key - Root signing key (base64)
   * @returns {Capability}
   */
  static deserialize(token, key) {
    try {
      const payload = JSON.parse(Buffer.from(token, 'base64url').toString());
      
      if (payload.v !== VERSION) {
        throw new Error(`Unsupported version: ${payload.v}`);
      }

      const cap = new Capability({
        identifier: payload.id,
        key,
        location: payload.loc,
        ttl: payload.exp - payload.iat,
        caveats: payload.cav,
        delegationDepth: payload.dep || 0,
        parentId: payload.pid
      });

      // Verify signature
      cap.signature = payload.sig;
      if (!cap.verify()) {
        throw new Error('Invalid signature');
      }

      return cap;
    } catch (e) {
      throw new Error(`Deserialization failed: ${e.message}`);
    }
  }

  // ─── Verification ─────────────────────────────────────────────────

  /**
   * Verify signature integrity
   * @returns {boolean}
   */
  verify() {
    const expected = this._sign();
    return timingSafeEqual(Buffer.from(this.signature), Buffer.from(expected));
  }

  /**
   * Check if capability satisfies all caveats for a given context
   * @param {Object} context - Authorization context
   * @param {string} context.agentId - Requesting agent ID
   * @param {string} context.ip - Requesting IP
   * @param {string} context.resource - Target resource
   * @param {string} context.action - Requested action
   * @param {Object} [context.custom] - Custom context for custom caveats
   * @returns {{ valid: boolean, reason?: string }}
   */
  authorize(context) {
    // Check expiry
    if (Date.now() > this.expiresAt) {
      return { valid: false, reason: 'Capability expired' };
    }

    // Check each caveat
    for (const caveat of this.caveats) {
      const result = this._checkCaveat(caveat, context);
      if (!result.valid) {
        return result;
      }
    }

    return { valid: true };
  }

  // ─── Private Methods ──────────────────────────────────────────────

  _addCaveat(caveat) {
    if (this.caveats.length >= MAX_CAVEATS) {
      throw new Error(`Max caveats exceeded: ${MAX_CAVEATS}`);
    }
    this.caveats.push(caveat);
    this.signature = this._sign();
  }

  _sign() {
    const payload = `${this.identifier}|${this.location}|${this.issuedAt}|${this.expiresAt}|${JSON.stringify(this.caveats)}|${this.delegationDepth}|${this.parentId || ''}`;
    return createHmac(ALGORITHM, this.key).update(payload).digest('base64url');
  }

  _checkCaveat(caveat, context) {
    switch (caveat.type) {
      case 'time':
        if (context.timestamp && context.timestamp > caveat.condition.before) {
          return { valid: false, reason: 'Time caveat violated' };
        }
        break;

      case 'ip':
        if (context.ip && !this._matchIP(context.ip, caveat.condition.allowed)) {
          return { valid: false, reason: 'IP not allowed' };
        }
        break;

      case 'agent':
        if (context.agentId && !caveat.condition.allowed.includes(context.agentId)) {
          return { valid: false, reason: 'Agent not authorized' };
        }
        break;

      case 'resource':
        if (context.resource && !this._matchResource(context.resource, caveat.condition.resource)) {
          return { valid: false, reason: `Resource access denied: ${context.resource}` };
        }
        if (context.action && caveat.condition.actions !== '*' && !caveat.condition.actions.includes(context.action)) {
          return { valid: false, reason: `Action not allowed: ${context.action}` };
        }
        break;

      case 'action':
        if (context.action && !caveat.condition.allowed.includes(context.action)) {
          return { valid: false, reason: `Action not allowed: ${context.action}` };
        }
        break;

      case 'delegation':
        // Already checked during delegation
        break;

      case 'custom':
        if (context.custom && context.custom[caveat.condition.predicate]) {
          const fn = context.custom[caveat.condition.predicate];
          if (typeof fn === 'function' && !fn(caveat.condition.params, context)) {
            return { valid: false, reason: `Custom caveat failed: ${caveat.condition.predicate}` };
          }
        }
        break;
    }
    return { valid: true };
  }

  _matchIP(ip, allowed) {
    for (const pattern of allowed) {
      if (pattern.includes('/')) {
        // CIDR match
        if (this._cidrMatch(ip, pattern)) return true;
      } else if (pattern === ip || pattern === '*') {
        return true;
      }
    }
    return false;
  }

  _cidrMatch(ip, cidr) {
    const [rangeIp, bits] = cidr.split('/');
    const mask = parseInt(bits, 10);
    const ipParts = ip.split('.').map(Number);
    const rangeParts = rangeIp.split('.').map(Number);
    
    for (let i = 0; i < 4; i++) {
      const maskByte = mask >= 8 ? 255 : (mask > 0 ? (255 << (8 - mask)) & 255 : 0);
      if ((ipParts[i] & maskByte) !== (rangeParts[i] & maskByte)) return false;
      mask -= 8;
    }
    return true;
  }

  _matchResource(requested, pattern) {
    // Convert glob pattern to regex
    const regexPattern = pattern
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.');
    return new RegExp(`^${regexPattern}$`).test(requested);
  }
}

// ─── Capability Store (for revocation/validation) ───────────────────

export class CapabilityStore {
  constructor() {
    this.tokens = new Map(); // identifier -> { token, revoked, metadata }
    this.revocationList = new Set(); // identifiers
    this.keyRotations = new Map(); // keyId -> key
    this.currentKeyId = 'root';
    this.rootKey = randomBytes(32).toString('base64');
    this.keyRotations.set(this.currentKeyId, this.rootKey);
  }

  /**
   * Issue a new capability
   * @param {Object} opts
   * @param {string} opts.identifier
   * @param {string} [opts.keyId] - Key to use for signing
   * @param {Caveat[]} [opts.caveats]
   * @param {number} [opts.ttl]
   * @param {Object} [opts.metadata]
   * @returns {Capability}
   */
  issue({ identifier, keyId = this.currentKeyId, caveats = [], ttl, metadata = {} }) {
    const key = this.keyRotations.get(keyId);
    if (!key) throw new Error(`Key not found: ${keyId}`);

    const cap = new Capability({
      identifier,
      key,
      caveats,
      ttl
    });

    this.tokens.set(identifier, {
      token: cap,
      revoked: false,
      metadata,
      issuedAt: Date.now(),
      keyId
    });

    return cap;
  }

  /**
   * Revoke a capability
   * @param {string} identifier
   * @returns {boolean}
   */
  revoke(identifier) {
    const entry = this.tokens.get(identifier);
    if (entry) {
      entry.revoked = true;
      this.revocationList.add(identifier);
      return true;
    }
    return false;
  }

  /**
   * Check if capability is revoked
   * @param {string} identifier
   * @returns {boolean}
   */
  isRevoked(identifier) {
    return this.revocationList.has(identifier);
  }

  /**
   * Validate and authorize a capability
   * @param {string} tokenString - Serialized capability
   * @param {Object} context - Authorization context
   * @returns {{ valid: boolean, capability?: Capability, reason?: string }}
   */
  async authorize(tokenString, context) {
    try {
      // Try each known key
      for (const [keyId, key] of this.keyRotations.entries()) {
        try {
          const cap = Capability.deserialize(tokenString, key);
          
          // Check revocation
          if (this.isRevoked(cap.identifier)) {
            return { valid: false, reason: 'Capability revoked' };
          }

          // Check expiry
          if (Date.now() > cap.expiresAt) {
            return { valid: false, reason: 'Capability expired' };
          }

          // Authorize
          const auth = cap.authorize(context);
          if (auth.valid) {
            return { valid: true, capability: cap };
          }
          return auth;
        } catch (e) {
          // Try next key
        }
      }
      return { valid: false, reason: 'Invalid capability or unknown key' };
    } catch (e) {
      return { valid: false, reason: e.message };
    }
  }

  /**
   * Rotate signing key
   * @param {string} newKeyId
   * @param {string} [newKey] - Base64 key, generated if not provided
   */
  rotateKey(newKeyId, newKey = randomBytes(32).toString('base64')) {
    this.keyRotations.set(newKeyId, newKey);
    this.currentKeyId = newKeyId;
  }

  /**
   * Get capability metadata
   * @param {string} identifier
   * @returns {Object|null}
   */
  getMetadata(identifier) {
    const entry = this.tokens.get(identifier);
    return entry ? { ...entry, token: undefined } : null;
  }

  /**
   * List all capabilities (admin)
   * @returns {Object[]}
   */
  list() {
    return Array.from(this.tokens.entries()).map(([id, entry]) => ({
      identifier: id,
      revoked: entry.revoked,
      issuedAt: entry.issuedAt,
      keyId: entry.keyId,
      metadata: entry.metadata,
      expiresAt: entry.token.expiresAt,
      delegationDepth: entry.token.delegationDepth
    }));
  }
}

// ─── Built-in Caveat Predicates ─────────────────────────────────────

export const CaveatPredicates = {
  /**
   * Require capability to be presented within time window
   * @param {Object} params - { windowMs: number }
   */
  recent: (params, context) => {
    const age = Date.now() - (context.timestamp || Date.now());
    return age <= (params.windowMs || 60000);
  },

  /**
   * Require specific capability chain
   * @param {Object} params - { requiredCapability: string }
   */
  requiresCapability: (params, context) => {
    return context.capabilities?.includes(params.requiredCapability) || false;
  },

  /**
   * Limit rate of use
   * @param {Object} params - { maxUses: number, windowMs: number }
   */
  rateLimit: (params, context) => {
    // Would need external rate limiter state
    return true; // Placeholder
  }
};

// ─── Helper: Create Root Capability ─────────────────────────────────

export function createRootCapability(key, identifier = 'root') {
  return new Capability({
    identifier,
    key,
    caveats: []
  });
}

export default { Capability, CapabilityStore, CaveatPredicates, createRootCapability };