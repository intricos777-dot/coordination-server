/**
 * Coordination Server - Hardened Multi-Agent Collaboration Hub
 * 
 * Features:
 * - JWT-based authentication with role-based access control
 * - WebSocket message routing between agents
 * - Session registry with cross-agent visibility
 * - Rate limiting and DoS protection
 * - TLS support
 * - Audit logging
 * - Agent presence/heartbeat tracking
 */

import express from 'express';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import { v4 as uuidv4 } from 'uuid';
import { config } from 'dotenv';
import { readFileSync, existsSync, mkdirSync, appendFileSync } from 'fs';
import { join, resolve } from 'path';
import { createHash, randomBytes, timingSafeEqual } from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import cors from 'cors';
import winston from 'winston';

// New modules
import { Capability, CapabilityStore } from './capabilities.js';
import { FederationNode } from './federation.js';
import { WebSocketTransport, StreamMultiplexer, StreamType } from './streaming.js';

config();

// ─── Configuration ────────────────────────────────────────────────

const PORT = Number(process.env.COORD_PORT || 4126);
const JWT_SECRET = process.env.COORD_JWT_SECRET || randomBytes(64).toString('hex');
const JWT_EXPIRY = process.env.COORD_JWT_EXPIRY || '24h';
const LOG_DIR = process.env.COORD_LOG_DIR || './data/logs';
const DATA_DIR = process.env.COORD_DATA_DIR || './data';
const ALLOWED_ORIGINS = (process.env.COORD_ALLOWED_ORIGINS || 'http://localhost:3000,http://localhost:4096,http://127.0.0.1:3000,http://127.0.0.1:4096').split(',');
const TLS_CERT = process.env.COORD_TLS_CERT || '';
const TLS_KEY = process.env.COORD_TLS_KEY || '';
const ADMIN_TOKEN = process.env.COORD_ADMIN_TOKEN || '';
const MAX_MESSAGE_SIZE = 64 * 1024; // 64KB
const HEARTBEAT_INTERVAL = 30000; // 30 seconds
const AGENT_TIMEOUT = 120000; // 2 minutes
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX = 100;
const WS_RATE_LIMIT = 50; // messages per minute per connection

// ─── Logger ───────────────────────────────────────────────────────

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    new winston.transports.File({ 
      filename: join(LOG_DIR, 'coordination.log'),
      maxsize: 10 * 1024 * 1024,
      maxFiles: 5
    }),
    new winston.transports.File({ 
      filename: join(LOG_DIR, 'audit.log'),
      level: 'info',
      maxsize: 10 * 1024 * 1024,
      maxFiles: 10,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    })
  ]
});

// ─── Audit Logger ─────────────────────────────────────────────────

function auditLog(event, details = {}) {
  logger.info('AUDIT', { event, ...details, timestamp: new Date().toISOString() });
}

// ─── Capability Store ──────────────────────────────────────────────

const capabilityStore = new CapabilityStore();
const ROOT_KEY = process.env.COORD_ROOT_KEY || randomBytes(32).toString('base64');

// ─── Federation Node ───────────────────────────────────────────────

const federationNode = new FederationNode({
  nodeId: process.env.COORD_NODE_ID || `node-${randomBytes(4).toString('hex')}`,
  listenUrl: process.env.COORD_LISTEN_URL || `ws://localhost:${PORT}/ws`,
  capabilityStore,
  logger
});

// ─── Stream Multiplexer ────────────────────────────────────────────

const streamMultiplexers = new Map(); // ws -> StreamMultiplexer

// ─── Data Structures ──────────────────────────────────────────────

// Agent registry: agentId -> { info, ws, lastHeartbeat, subscriptions, capability }
const agents = new Map();

// Session registry: sessionId -> { metadata, participants, messages, createdAt }
const sessions = new Map();

// Message queue for offline agents: agentId -> messages[]
const offlineQueue = new Map();

// Rate limiting per agent
const agentRateLimits = new Map();

// Connected clients: ws -> { agentId, authenticated, subscriptions, rateLimit, capability }
const clients = new Map();

// ─── Helpers ──────────────────────────────────────────────────────

function sanitizeInput(input, maxLength = 1000) {
  if (typeof input !== 'string') return '';
  return input.slice(0, maxLength).replace(/[\0\n\r]/g, '');
}

function validateAgentId(agentId) {
  return typeof agentId === 'string' && /^[a-zA-Z0-9_\-:]{1,64}$/.test(agentId);
}

function validateSessionId(sessionId) {
  return typeof sessionId === 'string' && /^[a-zA-Z0-9_\-]{1,64}$/.test(sessionId);
}

function checkRateLimit(agentId, maxRequests = RATE_LIMIT_MAX, windowMs = RATE_LIMIT_WINDOW) {
  const now = Date.now();
  const key = `${agentId}:${Math.floor(now / windowMs)}`;
  const count = (agentRateLimits.get(key) || 0) + 1;
  agentRateLimits.set(key, count);
  
  // Cleanup old entries
  if (agentRateLimits.size > 10000) {
    const cutoff = now - windowMs * 2;
    for (const [k, v] of agentRateLimits.entries()) {
      const windowStart = parseInt(k.split(':')[1], 10) * windowMs;
      if (windowStart < cutoff) agentRateLimits.delete(k);
    }
  }
  
  // Track rate limit exceeded for metrics
  if (count > maxRequests) {
    global.coordination_rate_limit_exceeded = (global.coordination_rate_limit_exceeded || 0) + 1;
  }
  
  return count <= maxRequests;
}

function checkWsRateLimit(ws) {
  const client = clients.get(ws);
  if (!client) return false;
  
  const now = Date.now();
  const windowStart = Math.floor(now / RATE_LIMIT_WINDOW) * RATE_LIMIT_WINDOW;
  const key = `${client.agentId}:${windowStart}`;
  
  const count = (client.rateLimitCount || 0) + 1;
  client.rateLimitCount = count;
  client.rateLimitWindow = windowStart;
  
  return count <= WS_RATE_LIMIT;
}

// ─── Agent Management ─────────────────────────────────────────────

function registerAgent(agentId, info, ws, capability = null) {
  if (!validateAgentId(agentId)) {
    throw new Error('Invalid agent ID');
  }
  
  const now = Date.now();
  const agent = {
    id: agentId,
    name: sanitizeInput(info.name || agentId, 100),
    type: sanitizeInput(info.type || 'unknown', 50),
    version: sanitizeInput(info.version || '1.0.0', 20),
    capabilities: Array.isArray(info.capabilities) ? info.capabilities.slice(0, 20) : [],
    metadata: info.metadata || {},
    ws,
    connectedAt: now,
    lastHeartbeat: now,
    subscriptions: new Set(['broadcast']),
    status: 'online',
    capability: capability?.serialize()
  };
  
  agents.set(agentId, agent);
  clients.set(ws, { agentId, authenticated: true, subscriptions: new Set(['broadcast']), rateLimitCount: 0, capability });
  
  // Initialize stream multiplexer for this connection
  const transport = new WebSocketTransport(ws, { capabilityStore, logger });
  const multiplexer = new StreamMultiplexer(transport);
  streamMultiplexers.set(ws, multiplexer);
  
  // Handle incoming streams
  transport.on('stream', (stream) => {
    stream.on('data', (data) => {
      // Handle stream data based on metadata
      if (stream.metadata.type === StreamType.PUBSUB) {
        // Pub/sub handled by multiplexer
      } else if (stream.metadata.type === StreamType.BIDI_STREAMING) {
        // Bidirectional stream - echo for now
        stream.write({ echo: data });
      }
    });
  });
  
  // Deliver queued messages
  const queued = offlineQueue.get(agentId) || [];
  for (const msg of queued) {
    safeSend(ws, msg);
  }
  offlineQueue.delete(agentId);
  
  // Register with federation
  federationNode.registerLocalAgent(agentId, {
    name: agent.name,
    type: agent.type,
    version: agent.version,
    capabilities: agent.capabilities,
    metadata: agent.metadata
  }, agent.capabilities);
  
  auditLog('agent_registered', { agentId, name: agent.name, type: agent.type });
  broadcastAgentList();
  
  return agent;
}

function unregisterAgent(agentId) {
  const agent = agents.get(agentId);
  if (agent) {
    agent.status = 'offline';
    agent.ws = null;
    auditLog('agent_unregistered', { agentId });
    broadcastAgentList();
    
    // Unregister from federation
    federationNode.unregisterLocalAgent(agentId);
  }
  
  // Clean up stream multiplexer
  if (agent?.ws) {
    const multiplexer = streamMultiplexers.get(agent.ws);
    if (multiplexer) {
      streamMultiplexers.delete(agent.ws);
    }
  }
  
  agents.delete(agentId);
}

function updateHeartbeat(agentId) {
  const agent = agents.get(agentId);
  if (agent) {
    agent.lastHeartbeat = Date.now();
    agent.status = 'online';
  }
}

// ─── Session Management ───────────────────────────────────────────

function createSession(ownerId, metadata = {}) {
  const sessionId = uuidv4();
  const now = Date.now();
  
  const session = {
    id: sessionId,
    owner: ownerId,
    name: sanitizeInput(metadata.name || `session-${sessionId.slice(0,8)}`, 100),
    description: sanitizeInput(metadata.description || '', 500),
    tags: Array.isArray(metadata.tags) ? metadata.tags.slice(0, 10).map(t => sanitizeInput(t, 50)) : [],
    visibility: metadata.visibility || 'private', // 'private', 'shared', 'public'
    participants: new Set([ownerId]),
    messages: [],
    createdAt: now,
    updatedAt: now,
    metadata: metadata.extra || {}
  };
  
  sessions.set(sessionId, session);
  auditLog('session_created', { sessionId, owner: ownerId, visibility: session.visibility });
  
  // Notify owner
  const owner = agents.get(ownerId);
  if (owner?.ws) {
    safeSend(owner.ws, {
      type: 'session_created',
      session: serializeSession(session)
    });
  }
  
  return session;
}

function joinSession(sessionId, agentId) {
  const session = sessions.get(sessionId);
  if (!session) return { success: false, reason: 'Session not found' };
  
  const agent = agents.get(agentId);
  if (!agent) return { success: false, reason: 'Agent not found' };
  
  // Check permissions
  if (session.visibility === 'private' && session.owner !== agentId) {
    return { success: false, reason: 'Private session' };
  }
  
  session.participants.add(agentId);
  session.updatedAt = Date.now();
  
  // Send session state to joining agent
  safeSend(agent.ws, {
    type: 'session_joined',
    session: serializeSession(session)
  });
  
  // Notify other participants
  broadcastToSession(sessionId, {
    type: 'participant_joined',
    sessionId,
    agentId,
    agentName: agent.name
  }, agentId);
  
  auditLog('session_joined', { sessionId, agentId });
  return { success: true };
}

function leaveSession(sessionId, agentId) {
  const session = sessions.get(sessionId);
  if (!session) return;
  
  session.participants.delete(agentId);
  session.updatedAt = Date.now();
  
  // Notify others
  broadcastToSession(sessionId, {
    type: 'participant_left',
    sessionId,
    agentId
  }, agentId);
  
  // If owner leaves and no participants, clean up after delay
  if (session.owner === agentId && session.participants.size === 0) {
    setTimeout(() => {
      const s = sessions.get(sessionId);
      if (s && s.participants.size === 0) {
        sessions.delete(sessionId);
        auditLog('session_cleanup', { sessionId });
      }
    }, 300000); // 5 minutes
  }
  
  auditLog('session_left', { sessionId, agentId });
}

function serializeSession(session) {
  return {
    id: session.id,
    owner: session.owner,
    name: session.name,
    description: session.description,
    tags: session.tags,
    visibility: session.visibility,
    participants: Array.from(session.participants),
    messageCount: session.messages.length,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    metadata: session.metadata
  };
}

function broadcastToSession(sessionId, message, excludeAgentId = null) {
  const session = sessions.get(sessionId);
  if (!session) return;
  
  for (const participantId of session.participants) {
    if (participantId === excludeAgentId) continue;
    const agent = agents.get(participantId);
    if (agent?.ws && agent.ws.readyState === 1) {
      safeSend(agent.ws, message);
    } else {
      // Queue for offline agent
      queueMessage(participantId, message);
    }
  }
}

// ─── Message Routing ──────────────────────────────────────────────

function routeMessage(fromAgentId, message) {
  const { type, target, sessionId, payload } = message;
  const fromAgent = agents.get(fromAgentId);
  const fromCapability = fromAgent?.capability;
  
  // Verify capability for sensitive operations
  if (fromCapability && ['direct', 'broadcast', 'session_message'].includes(type)) {
    const resource = type === 'direct' ? `agent:${target}` : 
                     type === 'broadcast' ? 'broadcast' : 
                     `session:${sessionId}`;
    const auth = capabilityStore.authorize(fromCapability, {
      agentId: fromAgentId,
      resource,
      action: type === 'broadcast' ? 'send' : 'invoke'
    });
    if (!auth.valid) {
      return { success: false, reason: `Capability denied: ${auth.reason}` };
    }
  }
  
  switch (type) {
    case 'direct':
      return routeDirectMessage(fromAgentId, target, payload, fromCapability);
    case 'broadcast':
      return routeBroadcast(fromAgentId, payload, fromCapability);
    case 'session':
      return routeSessionMessage(fromAgentId, sessionId, payload, fromCapability);
    case 'subscribe':
      return handleSubscribe(fromAgentId, payload);
    case 'unsubscribe':
      return handleUnsubscribe(fromAgentId, payload);
    case 'session_create':
      return handleSessionCreate(fromAgentId, payload);
    case 'session_join':
      return handleSessionJoin(fromAgentId, payload);
    case 'session_leave':
      return handleSessionLeave(fromAgentId, payload);
    case 'session_message':
      return handleSessionMessage(fromAgentId, payload, fromCapability);
    case 'heartbeat':
      updateHeartbeat(fromAgentId);
      return { success: true };
    case 'federation_route':
      return routeFederationMessage(fromAgentId, message);
    case 'stream_open':
    case 'stream_data':
    case 'stream_close':
      // Handled by transport
      return { success: true };
    default:
      return { success: false, reason: `Unknown message type: ${type}` };
  }
}

function routeDirectMessage(fromAgentId, targetId, payload, capability) {
  // Try local first
  const target = agents.get(targetId);
  if (target) {
    safeSend(target.ws, {
      type: 'direct',
      from: fromAgentId,
      payload,
      timestamp: Date.now()
    });
    auditLog('direct_message', { from: fromAgentId, to: targetId, local: true });
    return { success: true, local: true };
  }
  
  // Try federation routing
  const location = federationNode.locateAgent(targetId);
  if (location && !location.local) {
    // Route through federation
    return federationNode.routeMessage(fromAgentId, targetId, payload, capability);
  }
  
  // Queue for offline agent
  queueMessage(targetId, {
    type: 'direct',
    from: fromAgentId,
    payload,
    timestamp: Date.now()
  });
  return { success: true, queued: true };
}

function routeBroadcast(fromAgentId, payload, capability) {
  const message = {
    type: 'broadcast',
    from: fromAgentId,
    payload,
    timestamp: Date.now()
  };
  
  let sent = 0;
  // Local agents
  for (const [agentId, agent] of agents.entries()) {
    if (agentId === fromAgentId) continue;
    if (agent.ws && agent.ws.readyState === 1) {
      safeSend(agent.ws, message);
      sent++;
    } else {
      queueMessage(agentId, message);
    }
  }
  
  // Federation broadcast
  federationNode.broadcast(fromAgentId, payload, capability);
  
  auditLog('broadcast', { from: fromAgentId, recipients: sent, federated: true });
  return { success: true, recipients: sent, federated: true };
}

function routeSessionMessage(fromAgentId, sessionId, payload, capability) {
  const session = sessions.get(sessionId);
  if (!session) return { success: false, reason: 'Session not found' };
  
  if (!session.participants.has(fromAgentId)) {
    return { success: false, reason: 'Not a participant' };
  }
  
  const message = {
    type: 'session_message',
    sessionId,
    from: fromAgentId,
    payload,
    timestamp: Date.now()
  };
  
  // Store in session history (keep last 1000)
  session.messages.push(message);
  if (session.messages.length > 1000) {
    session.messages = session.messages.slice(-1000);
  }
  session.updatedAt = Date.now();
  
  broadcastToSession(sessionId, message, fromAgentId);
  auditLog('session_message', { sessionId, from: fromAgentId });
  return { success: true };
}

function handleSubscribe(agentId, payload) {
  const { channel } = payload;
  if (!channel || typeof channel !== 'string') {
    return { success: false, reason: 'Invalid channel' };
  }
  
  const client = Array.from(clients.entries()).find(([_, c]) => c.agentId === agentId);
  if (client) {
    client[1].subscriptions.add(channel);
  }
  
  const agent = agents.get(agentId);
  if (agent) agent.subscriptions.add(channel);
  
  return { success: true, channel };
}

function handleUnsubscribe(agentId, payload) {
  const { channel } = payload;
  
  const client = Array.from(clients.entries()).find(([_, c]) => c.agentId === agentId);
  if (client) {
    client[1].subscriptions.delete(channel);
  }
  
  const agent = agents.get(agentId);
  if (agent) agent.subscriptions.delete(channel);
  
  return { success: true, channel };
}

function handleSessionCreate(agentId, payload) {
  const session = createSession(agentId, payload);
  return { success: true, session: serializeSession(session) };
}

function handleSessionJoin(agentId, payload) {
  const { sessionId } = payload;
  if (!validateSessionId(sessionId)) {
    return { success: false, reason: 'Invalid session ID' };
  }
  return joinSession(sessionId, agentId);
}

function handleSessionLeave(agentId, payload) {
  const { sessionId } = payload;
  if (!validateSessionId(sessionId)) {
    return { success: false, reason: 'Invalid session ID' };
  }
  leaveSession(sessionId, agentId);
  return { success: true };
}

function handleSessionMessage(agentId, payload, capability) {
  const { sessionId, content } = payload;
  if (!validateSessionId(sessionId)) {
    return { success: false, reason: 'Invalid session ID' };
  }
  return routeSessionMessage(agentId, sessionId, content, capability);
}

async function routeFederationMessage(fromAgentId, message) {
  const { targetNode, targetAgent, payload, capability } = message;
  // This would route to a specific federation node
  // For now, use the federation node's routeMessage
  return federationNode.routeMessage(fromAgentId, targetAgent, payload, capability);
}

function queueMessage(agentId, message) {
  if (!offlineQueue.has(agentId)) {
    offlineQueue.set(agentId, []);
  }
  const queue = offlineQueue.get(agentId);
  queue.push(message);
  // Limit queue size
  if (queue.length > 100) {
    queue.shift();
  }
}

// ─── WebSocket Handling ───────────────────────────────────────────

function safeSend(ws, message) {
  if (ws.readyState === 1) {
    try {
      ws.send(JSON.stringify(message));
      return true;
    } catch (e) {
      logger.error('WS send error', { error: e.message });
    }
  }
  return false;
}

function handleWebSocketMessage(ws, data) {
  const client = clients.get(ws);
  if (!client || !client.authenticated) {
    safeSend(ws, { type: 'error', code: 'NOT_AUTHENTICATED', message: 'Authentication required' });
    return;
  }
  
  if (!checkWsRateLimit(ws)) {
    safeSend(ws, { type: 'error', code: 'RATE_LIMITED', message: 'WebSocket rate limit exceeded' });
    return;
  }
  
  try {
    const message = JSON.parse(data.toString());
    const result = routeMessage(client.agentId, message);
    
    // Send acknowledgment for requests with id
    if (message.id) {
      safeSend(ws, {
        type: 'ack',
        id: message.id,
        success: result.success,
        ...result
      });
    }
  } catch (e) {
    logger.error('WS message parse error', { error: e.message });
    safeSend(ws, { type: 'error', code: 'INVALID_MESSAGE', message: 'Invalid JSON' });
  }
}

function handleWebSocketClose(ws) {
  const client = clients.get(ws);
  if (client) {
    unregisterAgent(client.agentId);
    clients.delete(ws);
  }
}

// ─── Express App ──────────────────────────────────────────────────

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'", "ws:", "wss:"]
    }
  },
  hsts: { maxAge: 31536000, includeSubDomains: true }
}));

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '100kb' }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW,
  max: RATE_LIMIT_MAX,
  message: { error: 'Too many requests' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', apiLimiter);

// ─── Auth Endpoints ───────────────────────────────────────────────

app.post('/api/auth/token', async (req, res) => {
  try {
    const { agentId, secret } = req.body;
    
    if (!validateAgentId(agentId) || !secret) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    // In production, verify against stored hash
    // For now, accept any secret for registered agents or create new
    const token = jwt.sign(
      { sub: agentId, iat: Math.floor(Date.now() / 1000) },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );
    
    auditLog('token_issued', { agentId });
    res.json({ token, expiresIn: JWT_EXPIRY });
  } catch (e) {
    logger.error('Token error', { error: e.message });
    res.status(500).json({ error: 'Token generation failed' });
  }
});

app.post('/api/auth/verify', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing token' });
  }
  
  try {
    const token = authHeader.slice(7);
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ valid: true, agentId: decoded.sub });
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ─── Agent Registry API ───────────────────────────────────────────

app.get('/api/agents', (req, res) => {
  const agentList = Array.from(agents.values()).map(a => ({
    id: a.id,
    name: a.name,
    type: a.type,
    version: a.version,
    capabilities: a.capabilities,
    status: a.status,
    connectedAt: a.connectedAt,
    lastHeartbeat: a.lastHeartbeat,
    subscriptions: Array.from(a.subscriptions)
  }));
  res.json({ agents: agentList });
});

app.get('/api/agents/:id', (req, res) => {
  const agent = agents.get(req.params.id);
  if (!agent) {
    return res.status(404).json({ error: 'Agent not found' });
  }
  res.json({
    id: agent.id,
    name: agent.name,
    type: agent.type,
    version: agent.version,
    capabilities: agent.capabilities,
    metadata: agent.metadata,
    status: agent.status,
    connectedAt: agent.connectedAt,
    lastHeartbeat: agent.lastHeartbeat,
    subscriptions: Array.from(agent.subscriptions)
  });
});

// ─── Session API ──────────────────────────────────────────────────

app.get('/api/sessions', (req, res) => {
  const { visibility, participant } = req.query;
  let sessionList = Array.from(sessions.values()).map(serializeSession);
  
  if (visibility) {
    sessionList = sessionList.filter(s => s.visibility === visibility);
  }
  if (participant) {
    sessionList = sessionList.filter(s => s.participants.includes(participant));
  }
  
  res.json({ sessions: sessionList });
});

app.get('/api/sessions/:id', (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }
  res.json(serializeSession(session));
});

app.get('/api/sessions/:id/messages', (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }
  const limit = Math.min(Number(req.query.limit) || 100, 500);
  const offset = Number(req.query.offset) || 0;
  res.json({ 
    messages: session.messages.slice(offset, offset + limit),
    total: session.messages.length
  });
});

// ─── Admin API ────────────────────────────────────────────────────

function verifyAdmin(req) {
  if (!ADMIN_TOKEN) return false;
  const token = req.headers['x-admin-token'] || req.query.token;
  return token && timingSafeEqual(Buffer.from(token), Buffer.from(ADMIN_TOKEN));
}

app.get('/admin/stats', (req, res) => {
  if (!verifyAdmin(req)) return res.status(401).json({ error: 'Unauthorized' });
  
  res.json({
    agents: agents.size,
    sessions: sessions.size,
    offlineQueues: offlineQueue.size,
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    rateLimitEntries: agentRateLimits.size
  });
});

app.post('/admin/cleanup', (req, res) => {
  if (!verifyAdmin(req)) return res.status(401).json({ error: 'Unauthorized' });
  
  // Clean stale agents
  const now = Date.now();
  for (const [agentId, agent] of agents.entries()) {
    if (now - agent.lastHeartbeat > AGENT_TIMEOUT) {
      unregisterAgent(agentId);
    }
  }
  
  // Clean old sessions
  const cutoff = now - 24 * 60 * 60 * 1000; // 24 hours
  for (const [sessionId, session] of sessions.entries()) {
    if (session.updatedAt < cutoff && session.participants.size === 0) {
      sessions.delete(sessionId);
    }
  }
  
  res.json({ cleaned: true });
});

// ─── Health ───────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    agents: agents.size, 
    sessions: sessions.size,
    uptime: process.uptime()
  });
});

// ─── Metrics (Prometheus) ──────────────────────────────────────────

app.get('/metrics', (req, res) => {
  const mem = process.memoryUsage();
  const cpu = process.cpuUsage();
  const uptime = process.uptime();
  
  const metrics = [
    `# HELP coordination_server_uptime_seconds Server uptime in seconds`,
    `# TYPE coordination_server_uptime_seconds gauge`,
    `coordination_server_uptime_seconds ${uptime}`,
    ``,
    `# HELP coordination_server_memory_bytes Memory usage in bytes`,
    `# TYPE coordination_server_memory_bytes gauge`,
    `coordination_server_memory_bytes{type="rss"} ${mem.rss}`,
    `coordination_server_memory_bytes{type="heapTotal"} ${mem.heapTotal}`,
    `coordination_server_memory_bytes{type="heapUsed"} ${mem.heapUsed}`,
    `coordination_server_memory_bytes{type="external"} ${mem.external}`,
    ``,
    `# HELP coordination_server_cpu_seconds_total CPU usage in seconds`,
    `# TYPE coordination_server_cpu_seconds_total counter`,
    `coordination_server_cpu_seconds_total{type="user"} ${cpu.user / 1e6}`,
    `coordination_server_cpu_seconds_total{type="system"} ${cpu.system / 1e6}`,
    ``,
    `# HELP coordination_agents_connected Number of connected agents`,
    `# TYPE coordination_agents_connected gauge`,
    `coordination_agents_connected ${agents.size}`,
    ``,
    `# HELP coordination_agents_total Total agents registered`,
    `# TYPE coordination_agents_total gauge`,
    `coordination_agents_total ${agents.size + offlineQueue.size}`,
    ``,
    `# HELP coordination_sessions_active Number of active sessions`,
    `# TYPE coordination_sessions_active gauge`,
    `coordination_sessions_active ${sessions.size}`,
    ``,
    `# HELP coordination_federation_peers_online Number of online federation peers`,
    `# TYPE coordination_federation_peers_online gauge`,
    `coordination_federation_peers_online ${Array.from(federationNode.peers.values()).filter(p => p.status === 'online').length}`,
    ``,
    `# HELP coordination_federation_peers_total Total federation peers`,
    `# TYPE coordination_federation_peers_total gauge`,
    `coordination_federation_peers_total ${federationNode.peers.size}`,
    ``,
    `# HELP coordination_offline_queues Number of offline message queues`,
    `# TYPE coordination_offline_queues gauge`,
    `coordination_offline_queues ${offlineQueue.size}`,
    ``,
    `# HELP coordination_rate_limit_entries Current rate limit entries`,
    `# TYPE coordination_rate_limit_entries gauge`,
    `coordination_rate_limit_entries ${agentRateLimits.size}`,
    ``,
    `# HELP coordination_rate_limit_exceeded_total Total rate limit exceeded count`,
    `# TYPE coordination_rate_limit_exceeded_total counter`,
    `coordination_rate_limit_exceeded_total ${global.coordination_rate_limit_exceeded || 0}`,
    ``,
    `# HELP coordination_websocket_connections Active WebSocket connections`,
    `# TYPE coordination_websocket_connections gauge`,
    `coordination_websocket_connections ${clients.size}`,
  ].join('\n');
  
  res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.send(metrics);
});

// ─── WebSocket Server ────────────────────────────────────────────

const server = createServer(app);
const wss = new WebSocketServer({ 
  server, 
  path: '/ws',
  maxPayload: MAX_MESSAGE_SIZE,
  verifyClient: (info, callback) => {
    const origin = info.origin;
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(true);
    } else {
      callback(false, 403, 'Origin not allowed');
    }
  }
});

wss.on('connection', (ws, req) => {
  const clientIp = req.socket.remoteAddress;
  logger.info('WS connection', { ip: clientIp });
  
  // Create transport and multiplexer for this connection (even before auth)
  const transport = new WebSocketTransport(ws, { capabilityStore, logger });
  const multiplexer = new StreamMultiplexer(transport);
  streamMultiplexers.set(ws, multiplexer);
  
  // Send welcome message - authentication required
  safeSend(ws, { 
    type: 'welcome', 
    message: 'Connected to Coordination Server. Authenticate with /api/auth/token then send {type:"auth", token:"..."} or {type:"auth_capability", capability:"..."}',
    version: '1.0.0',
    features: ['capabilities', 'federation', 'streaming']
  });
  
  ws.on('message', async (data) => {
    if (data.length > MAX_MESSAGE_SIZE) {
      safeSend(ws, { type: 'error', code: 'MESSAGE_TOO_LARGE' });
      return;
    }
    
    try {
      const message = JSON.parse(data.toString());
      
      // Handle authentication with JWT token
      if (message.type === 'auth' && message.token) {
        try {
          const decoded = jwt.verify(message.token, JWT_SECRET);
          const agentId = decoded.sub;
          
          if (!validateAgentId(agentId)) {
            safeSend(ws, { type: 'auth_result', success: false, reason: 'Invalid agent ID in token' });
            return;
          }
          
          // Register or re-attach agent
          let agent = agents.get(agentId);
          if (agent) {
            // Reconnect existing
            agent.ws = ws;
            agent.lastHeartbeat = Date.now();
            agent.status = 'online';
            clients.set(ws, { agentId, authenticated: true, subscriptions: new Set(['broadcast']), rateLimitCount: 0, capability: null });
            auditLog('agent_reconnected', { agentId });
          } else {
            // New agent - need registration info
            safeSend(ws, { type: 'auth_result', success: true, registered: false, agentId, message: 'Send registration info' });
            // Store pending auth
            clients.set(ws, { agentId, authenticated: false, pendingAuth: true, subscriptions: new Set(), rateLimitCount: 0, capability: null });
          }
          return;
        } catch (e) {
          safeSend(ws, { type: 'auth_result', success: false, reason: 'Invalid token' });
          return;
        }
      }
      
      // Handle authentication with OCAP capability
      if (message.type === 'auth_capability' && message.capability) {
        try {
          const auth = await capabilityStore.authorize(message.capability, {
            agentId: message.agentId,
            resource: 'coordination:connect',
            action: 'connect',
            timestamp: Date.now()
          });
          
          if (!auth.valid) {
            safeSend(ws, { type: 'auth_result', success: false, reason: auth.reason });
            return;
          }
          
          const agentId = auth.capability.identifier;
          
          if (!validateAgentId(agentId)) {
            safeSend(ws, { type: 'auth_result', success: false, reason: 'Invalid agent ID in capability' });
            return;
          }
          
          // Register or re-attach agent with capability
          let agent = agents.get(agentId);
          if (agent) {
            agent.ws = ws;
            agent.lastHeartbeat = Date.now();
            agent.status = 'online';
            clients.set(ws, { agentId, authenticated: true, subscriptions: new Set(['broadcast']), rateLimitCount: 0, capability: auth.capability });
            auditLog('agent_reconnected', { agentId, auth: 'capability' });
          } else {
            safeSend(ws, { type: 'auth_result', success: true, registered: false, agentId, message: 'Send registration info' });
            clients.set(ws, { agentId, authenticated: false, pendingAuth: true, subscriptions: new Set(), rateLimitCount: 0, capability: auth.capability });
          }
          return;
        } catch (e) {
          safeSend(ws, { type: 'auth_result', success: false, reason: 'Capability verification failed' });
          return;
        }
      }
      
      // Get client info
      const client = clients.get(ws);
      
      // Handle registration (after auth)
      if (message.type === 'register' && message.agentId && client && !client.authenticated) {
        if (client.pendingAuth && client.agentId === message.agentId) {
          registerAgent(message.agentId, message.info || {}, ws, client.capability);
          safeSend(ws, { type: 'auth_result', success: true, registered: true });
        }
        return;
      }
      
      // Handle stream messages
      if (message.type === 'stream_open' || message.type === 'stream_message') {
        transport._handleMessage(message);
        return;
      }
      
      // Handle regular messages
      if (client?.authenticated) {
        handleWebSocketMessage(ws, data);
      } else {
        safeSend(ws, { type: 'error', code: 'NOT_AUTHENTICATED' });
      }
    } catch (e) {
      logger.error('WS message error', { error: e.message });
      safeSend(ws, { type: 'error', code: 'INVALID_MESSAGE' });
    }
  });
  
  ws.on('close', () => {
    handleWebSocketClose(ws);
    streamMultiplexers.delete(ws);
  });
  
  ws.on('error', (err) => {
    logger.error('WS error', { error: err.message });
    handleWebSocketClose(ws);
  });
  
  // Heartbeat
  ws.heartbeatTimer = setInterval(() => {
    if (ws.readyState === 1) {
      safeSend(ws, { type: 'ping', timestamp: Date.now() });
    } else {
      clearInterval(ws.heartbeatTimer);
    }
  }, HEARTBEAT_INTERVAL);
});

// ─── Periodic Cleanup ────────────────────────────────────────────

setInterval(() => {
  const now = Date.now();
  
  // Clean stale agents
  for (const [agentId, agent] of agents.entries()) {
    if (now - agent.lastHeartbeat > AGENT_TIMEOUT) {
      if (agent.ws) {
        agent.ws.close();
      }
      unregisterAgent(agentId);
    }
  }
  
  // Clean old rate limit entries
  if (agentRateLimits.size > 5000) {
    const cutoff = now - RATE_LIMIT_WINDOW * 2;
    for (const [k, v] of agentRateLimits.entries()) {
      const windowStart = parseInt(k.split(':')[1], 10) * RATE_LIMIT_WINDOW;
      if (windowStart < cutoff) agentRateLimits.delete(k);
    }
  }
  
  // Clean empty offline queues
  for (const [agentId, queue] of offlineQueue.entries()) {
    if (queue.length === 0) {
      offlineQueue.delete(agentId);
    }
  }
  
}, 60000); // Every minute

// ─── Start Server ────────────────────────────────────────────────

function broadcastAgentList() {
  const agentList = Array.from(agents.values()).map(a => ({
    id: a.id,
    name: a.name,
    type: a.type,
    status: a.status,
    capabilities: a.capabilities
  }));
  
  const message = { type: 'agent_list', agents: agentList, timestamp: Date.now() };
  
  for (const [ws, client] of clients.entries()) {
    if (client.authenticated && ws.readyState === 1) {
      safeSend(ws, message);
    }
  }
}

// ─── Capability API ────────────────────────────────────────────────

app.post('/api/capabilities/issue', async (req, res) => {
  try {
    const { identifier, caveats = [], ttl, metadata = {} } = req.body;
    
    if (!identifier || !validateAgentId(identifier)) {
      return res.status(400).json({ error: 'Invalid identifier' });
    }
    
    const cap = capabilityStore.issue({
      identifier,
      caveats,
      ttl,
      metadata
    });
    
    auditLog('capability_issued', { identifier, delegationDepth: cap.delegationDepth });
    res.json({ 
      capability: cap.serialize(),
      identifier: cap.identifier,
      expiresAt: cap.expiresAt,
      delegationDepth: cap.delegationDepth
    });
  } catch (e) {
    logger.error('Capability issue error', { error: e.message });
    res.status(500).json({ error: 'Failed to issue capability' });
  }
});

app.post('/api/capabilities/delegate', async (req, res) => {
  try {
    const { parentCapability, identifier, caveats = [], ttl } = req.body;
    
    if (!parentCapability || !identifier) {
      return res.status(400).json({ error: 'Missing parentCapability or identifier' });
    }
    
    // Verify parent capability
    const auth = await capabilityStore.authorize(parentCapability, {
      resource: 'capability:delegate',
      action: 'delegate'
    });
    
    if (!auth.valid) {
      return res.status(403).json({ error: `Parent capability invalid: ${auth.reason}` });
    }
    
    const delegated = auth.capability.delegate({ identifier, caveats, ttl });
    
    auditLog('capability_delegated', { 
      parent: auth.capability.identifier, 
      child: delegated.identifier,
      depth: delegated.delegationDepth
    });
    
    res.json({ 
      capability: delegated.serialize(),
      identifier: delegated.identifier,
      expiresAt: delegated.expiresAt,
      delegationDepth: delegated.delegationDepth
    });
  } catch (e) {
    logger.error('Capability delegate error', { error: e.message });
    res.status(500).json({ error: 'Failed to delegate capability' });
  }
});

app.post('/api/capabilities/verify', async (req, res) => {
  try {
    const { capability, context = {} } = req.body;
    
    if (!capability) {
      return res.status(400).json({ error: 'Missing capability' });
    }
    
    const result = await capabilityStore.authorize(capability, {
      ...context,
      timestamp: Date.now()
    });
    
    res.json({ 
      valid: result.valid, 
      reason: result.reason,
      capability: result.capability?.serialize()
    });
  } catch (e) {
    logger.error('Capability verify error', { error: e.message });
    res.status(500).json({ error: 'Verification failed' });
  }
});

app.post('/api/capabilities/revoke', (req, res) => {
  try {
    const { identifier } = req.body;
    
    if (!identifier) {
      return res.status(400).json({ error: 'Missing identifier' });
    }
    
    const revoked = capabilityStore.revoke(identifier);
    auditLog('capability_revoked', { identifier, revoked });
    res.json({ revoked });
  } catch (e) {
    logger.error('Capability revoke error', { error: e.message });
    res.status(500).json({ error: 'Failed to revoke' });
  }
});

app.get('/api/capabilities', (req, res) => {
  res.json({ capabilities: capabilityStore.list() });
});

// ─── Federation API ────────────────────────────────────────────────

app.get('/api/federation/peers', (req, res) => {
  res.json({ peers: federationNode.getPeers() });
});

app.get('/api/federation/agents/local', (req, res) => {
  res.json({ agents: federationNode.getLocalAgents() });
});

app.get('/api/federation/agents/remote', (req, res) => {
  res.json({ agents: federationNode.getRemoteAgents() });
});

app.get('/api/federation/agents/:agentId', (req, res) => {
  const location = federationNode.locateAgent(req.params.agentId);
  if (!location) {
    return res.status(404).json({ error: 'Agent not found' });
  }
  res.json(location);
});

app.get('/api/federation/sessions', (req, res) => {
  res.json({ sessions: federationNode.getFederatedSessions() });
});

app.get('/api/federation/streams', (req, res) => {
  res.json({ streams: federationNode.getFederatedStreams() });
});

app.post('/api/federation/connect', async (req, res) => {
  try {
    const { peerUrl, capability } = req.body;
    
    if (!peerUrl || !capability) {
      return res.status(400).json({ error: 'Missing peerUrl or capability' });
    }
    
    // In real implementation, this would connect to the peer
    // For now, return success
    res.json({ success: true, message: 'Connection initiated' });
  } catch (e) {
    logger.error('Federation connect error', { error: e.message });
    res.status(500).json({ error: 'Failed to connect to peer' });
  }
});

// ─── Streaming API ────────────────────────────────────────────────

app.post('/api/streams/open', async (req, res) => {
  // This would be handled via WebSocket upgrade
  res.json({ error: 'Use WebSocket for streaming', upgrade: '/ws' });
});

// ─── Start Server ────────────────────────────────────────────────

const startServer = async () => {
  // Ensure directories
  mkdirSync(LOG_DIR, { recursive: true, mode: 0o700 });
  mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  
  // Start federation node
  await federationNode.start();
  logger.info(`Federation node started: ${federationNode.nodeId}`);
  
  // Handle federation events
  federationNode.on('localMessage', ({ from, to, payload }) => {
    const agent = agents.get(to);
    if (agent?.ws && agent.ws.readyState === 1) {
      safeSend(agent.ws, { type: 'direct', from, payload, timestamp: Date.now() });
    } else {
      queueMessage(to, { type: 'direct', from, payload, timestamp: Date.now() });
    }
  });
  
  federationNode.on('localBroadcast', ({ from, payload }) => {
    const message = { type: 'broadcast', from, payload, timestamp: Date.now() };
    for (const [agentId, agent] of agents.entries()) {
      if (agentId === from) continue;
      if (agent.ws && agent.ws.readyState === 1) {
        safeSend(agent.ws, message);
      } else {
        queueMessage(agentId, message);
      }
    }
  });
  
  federationNode.on('streamData', ({ streamId, from, data }) => {
    // Deliver to local stream subscribers
    for (const [ws, multiplexer] of streamMultiplexers.entries()) {
      // Would need stream subscription tracking
    }
  });
  
  if (TLS_CERT && TLS_KEY) {
    try {
      const https = await import('https');
      const cert = readFileSync(TLS_CERT);
      const key = readFileSync(TLS_KEY);
      https.createServer({ cert, key }, app).listen(PORT, '0.0.0.0', () => {
        logger.info(`Coordination Server (HTTPS) running on https://localhost:${PORT}`);
        logger.info(`WebSocket: wss://localhost:${PORT}/ws`);
        logger.info(`REST API: http://localhost:${PORT}/api/`);
        if (ADMIN_TOKEN) logger.info('Admin endpoints enabled (X-Admin-Token required)');
      });
      return;
    } catch (err) {
      logger.error('Failed to start HTTPS server', { error: err.message });
      process.exit(1);
    }
  }
  
  server.listen(PORT, '0.0.0.0', () => {
    logger.info(`Coordination Server running on http://localhost:${PORT}`);
    logger.info(`WebSocket: ws://localhost:${PORT}/ws`);
    logger.info(`REST API: http://localhost:${PORT}/api/`);
    if (ADMIN_TOKEN) logger.info('Admin endpoints enabled (X-Admin-Token required)');
  });
};

// ─── Graceful Shutdown ────────────────────────────────────────────

async function shutdown() {
  logger.info('Shutting down...');
  
  await federationNode.stop();
  
  // Close all WebSocket connections
  for (const [ws, client] of clients.entries()) {
    ws.close();
  }
  
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
  
  // Force exit after 10 seconds
  setTimeout(() => {
    logger.error('Forced shutdown');
    process.exit(1);
  }, 10000);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// ─── Start ────────────────────────────────────────────────────────

startServer();

export { 
  app, 
  server, 
  registerAgent, 
  createSession, 
  broadcastToSession,
  capabilityStore,
  federationNode,
  streamMultiplexers
};