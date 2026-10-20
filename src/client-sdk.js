// Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
/**
 * Coordination Server Client SDK
 * 
 * Usage:
 *   import { CoordinationClient } from 'coordination-server/client-sdk.js';
 *   const client = new CoordinationClient({ serverUrl: 'ws://localhost:4126' });
 *   await client.connect({ agentId: 'lia-1', name: 'Lia', type: 'cli' });
 *   client.on('session_message', (msg) => console.log(msg));
 *   await client.joinSession('session-id');
 *   await client.sendSessionMessage('session-id', { text: 'Hello!' });
 */

export class CoordinationClient {
  constructor(options = {}) {
    this.serverUrl = options.serverUrl || 'ws://localhost:4126/ws';
    this.restUrl = options.restUrl || this.serverUrl.replace('ws://', 'http://').replace('wss://', 'https://').replace('/ws', '');
    this.agentId = options.agentId;
    this.name = options.name || this.agentId;
    this.type = options.type || 'unknown';
    this.version = options.version || '1.0.0';
    this.capabilities = options.capabilities || [];
    this.metadata = options.metadata || {};
    
    this.ws = null;
    this.token = null;
    this.capability = null;
    this.connected = false;
    this.authenticated = false;
    this.messageId = 0;
    this.pendingRequests = new Map();
    this.eventHandlers = new Map();
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = options.maxReconnectAttempts || 10;
    this.reconnectDelay = options.reconnectDelay || 2000;
    this.heartbeatTimer = null;
    this.requestTimeout = options.requestTimeout || 10000;
    
    // Stream management
    this.streams = new Map();
    this.streamId = 0;
  }
  
  // ─── Connection ─────────────────────────────────────────────────
  
  async connect(authOptions = {}) {
    this.agentId = authOptions.agentId || this.agentId;
    if (!this.agentId) throw new Error('agentId required');
    
    // Get auth token via REST API
    if (authOptions.token) {
      this.token = authOptions.token;
    } else if (authOptions.secret) {
      this.token = await this._getToken(this.agentId, authOptions.secret);
    } else {
      throw new Error('token or secret required for authentication');
    }
    
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.serverUrl);
      
      this.ws.onopen = () => {
        this.connected = true;
        this.reconnectAttempts = 0;
        this._send({ type: 'auth', token: this.token });
      };
      
      this.ws.onmessage = (event) => this._handleMessage(event.data);
      
      this.ws.onclose = () => {
        this.connected = false;
        this.authenticated = false;
        this._clearHeartbeat();
        this._handleDisconnect();
      };
      
      this.ws.onerror = (err) => {
        this.emit('error', err);
        if (!this.authenticated) reject(err);
      };
      
      // Wait for auth result
      const timeout = setTimeout(() => {
        reject(new Error('Connection timeout'));
      }, this.requestTimeout);
      
      this.once('auth_result', (result) => {
        clearTimeout(timeout);
        if (result.success) {
          this.authenticated = true;
          if (!result.registered) {
            // Send registration
            this._send({
              type: 'register',
              agentId: this.agentId,
              info: { name: this.name, type: this.type, version: this.version, capabilities: this.capabilities, metadata: this.metadata }
            });
          }
          this._startHeartbeat();
          resolve(this);
        } else {
          reject(new Error(result.reason || 'Authentication failed'));
        }
      });
    });
  }
  
  async _getToken(agentId, secret) {
    const res = await fetch(`${this.restUrl}/api/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentId, secret })
    });
    if (!res.ok) throw new Error('Failed to get token');
    const data = await res.json();
    return data.token;
  }
  
  // ─── Capability Authentication ─────────────────────────────────────
  
  /**
   * Connect using an OCAP capability token
   * @param {string} capabilityToken - Serialized capability
   */
  async connectWithCapability(capabilityToken) {
    this.capability = capabilityToken;
    this.agentId = Capability.deserialize(capabilityToken, '').identifier; // We can't verify without key, so parse identifier
    
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.serverUrl);
      
      this.ws.onopen = () => {
        this.connected = true;
        this.reconnectAttempts = 0;
        this._send({ type: 'auth_capability', capability: this.capability, agentId: this.agentId });
      };
      
      this.ws.onmessage = (event) => this._handleMessage(event.data);
      
      this.ws.onclose = () => {
        this.connected = false;
        this.authenticated = false;
        this._clearHeartbeat();
        this._handleDisconnect();
      };
      
      this.ws.onerror = (err) => {
        this.emit('error', err);
        if (!this.authenticated) reject(err);
      };
      
      const timeout = setTimeout(() => {
        reject(new Error('Connection timeout'));
      }, this.requestTimeout);
      
      this.once('auth_result', (result) => {
        clearTimeout(timeout);
        if (result.success) {
          this.authenticated = true;
          if (!result.registered) {
            this._send({
              type: 'register',
              agentId: this.agentId,
              info: { name: this.name, type: this.type, version: this.version, capabilities: this.capabilities, metadata: this.metadata }
            });
          }
          this._startHeartbeat();
          resolve(this);
        } else {
          reject(new Error(result.reason || 'Authentication failed'));
        }
      });
    });
  }
  
  /**
   * Request a capability from the server
   * @param {Object} options - Capability options
   * @returns {Promise<string>} Serialized capability
   */
  async requestCapability(options) {
    const res = await fetch(`${this.restUrl}/api/capabilities/issue`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`
      },
      body: JSON.stringify(options)
    });
    if (!res.ok) throw new Error('Failed to request capability');
    const data = await res.json();
    return data.capability;
  }
  
  /**
   * Delegate a capability
   * @param {string} parentCapability - Parent capability token
   * @param {Object} options - Delegation options
   * @returns {Promise<string>} Delegated capability
   */
  async delegateCapability(parentCapability, options) {
    const res = await fetch(`${this.restUrl}/api/capabilities/delegate`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`
      },
      body: JSON.stringify({ parentCapability, ...options })
    });
    if (!res.ok) throw new Error('Failed to delegate capability');
    const data = await res.json();
    return data.capability;
  }
  
  _startHeartbeat() {
    this.heartbeatTimer = setInterval(() => {
      if (this.connected && this.ws?.readyState === WebSocket.OPEN) {
        this._send({ type: 'heartbeat' });
      }
    }, 30000);
  }
  
  _clearHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }
  
  _handleDisconnect() {
    this.emit('disconnect');
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = this.reconnectDelay * Math.pow(1.5, this.reconnectAttempts - 1);
      setTimeout(() => this.connect(), delay);
    }
  }
  
  // ─── Message Handling ───────────────────────────────────────────
  
  _send(message) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    }
  }
  
  _handleMessage(data) {
    try {
      const message = JSON.parse(data);
      
      // Handle stream ack
      if (message.type === 'stream_ack' && message.streamId) {
        this.emit(`stream_ack_${message.streamId}`, message);
        return;
      }
      
      // Handle stream messages
      if (message.type === 'stream_message' && message.streamId) {
        const stream = this.streams.get(message.streamId);
        if (stream && message.message) {
          const streamMsg = JSON.parse(message.message);
          if (streamMsg.type === 'data') {
            stream.buffer.push(streamMsg.payload);
            if (stream.pendingRead) {
              stream.pendingRead(stream.buffer.shift());
              stream.pendingRead = null;
            }
          } else if (streamMsg.type === 'close') {
            stream.closed = true;
            if (stream.pendingRead) {
              stream.pendingRead(null);
              stream.pendingRead = null;
            }
          } else if (streamMsg.type === 'error') {
            stream.closed = true;
            if (stream.pendingRead) {
              stream.pendingRead(null);
              stream.pendingRead = null;
            }
            this.emit('error', streamMsg.payload);
          }
        }
        return;
      }
      
      // Handle request responses
      if (message.id && this.pendingRequests.has(message.id)) {
        const { resolve, reject } = this.pendingRequests.get(message.id);
        this.pendingRequests.delete(message.id);
        if (message.success) resolve(message);
        else reject(new Error(message.reason || 'Request failed'));
        return;
      }
      
      // Emit event
      this.emit(message.type, message);
      
    } catch (e) {
      this.emit('error', e);
    }
  }
  
  // ─── Request/Response ───────────────────────────────────────────
  
  _request(message) {
    return new Promise((resolve, reject) => {
      const id = ++this.messageId;
      message.id = id;
      
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new Error('Request timeout'));
      }, this.requestTimeout);
      
      this.pendingRequests.set(id, { resolve: (msg) => { clearTimeout(timeout); resolve(msg); }, reject });
      this._send(message);
    });
  }
  
  // ─── Session Management ─────────────────────────────────────────
  
  async createSession(options = {}) {
    const result = await this._request({ type: 'session_create', payload: options });
    return result.session;
  }
  
  async joinSession(sessionId) {
    const result = await this._request({ type: 'session_join', payload: { sessionId } });
    return result.success;
  }
  
  async leaveSession(sessionId) {
    const result = await this._request({ type: 'session_leave', payload: { sessionId } });
    return result.success;
  }
  
  async sendSessionMessage(sessionId, content) {
    const result = await this._request({ 
      type: 'session_message', 
      payload: { sessionId, content } 
    });
    return result.success;
  }
  
  async getSessionMessages(sessionId, limit = 100, offset = 0) {
    const res = await fetch(`${this.restUrl}/api/sessions/${sessionId}/messages?limit=${limit}&offset=${offset}`, {
      headers: { 'Authorization': `Bearer ${this.token}` }
    });
    if (!res.ok) throw new Error('Failed to fetch messages');
    return res.json();
  }
  
  async listSessions(filters = {}) {
    const params = new URLSearchParams();
    if (filters.visibility) params.set('visibility', filters.visibility);
    if (filters.participant) params.set('participant', filters.participant);
    
    const res = await fetch(`${this.restUrl}/api/sessions?${params}`, {
      headers: { 'Authorization': `Bearer ${this.token}` }
    });
    if (!res.ok) throw new Error('Failed to list sessions');
    return res.json();
  }
  
  // ─── Direct Messaging ───────────────────────────────────────────
  
  async sendDirectMessage(targetAgentId, payload) {
    const result = await this._request({ type: 'direct', target: targetAgentId, payload });
    return result.success;
  }
  
  async broadcast(payload) {
    const result = await this._request({ type: 'broadcast', payload });
    return result;
  }
  
  // ─── Subscriptions ──────────────────────────────────────────────
  
  async subscribe(channel) {
    const result = await this._request({ type: 'subscribe', payload: { channel } });
    return result.success;
  }
  
  async unsubscribe(channel) {
    const result = await this._request({ type: 'unsubscribe', payload: { channel } });
    return result.success;
  }
  
  // ─── Streaming ─────────────────────────────────────────────────────
  
  /**
   * Open a bidirectional stream
   * @param {string} type - Stream type: 'bidi', 'server', 'client', 'request_response'
   * @param {Object} metadata - Stream metadata
   * @returns {AsyncIterable} Async iterator for stream data
   */
  async openStream(type = 'bidi', metadata = {}) {
    const streamId = `stream-${++this.streamId}`;
    
    return new Promise((resolve, reject) => {
      // Create stream object
      const stream = {
        streamId,
        type,
        metadata,
        closed: false,
        buffer: [],
        pendingRead: null,
        
        // Async iterator
        [Symbol.asyncIterator]: async function* () {
          while (!this.closed) {
            if (this.buffer.length > 0) {
              yield this.buffer.shift();
            } else {
              yield await new Promise(r => { this.pendingRead = r; });
            }
          }
        },
        
        write: (data, endStream = false) => {
          this._sendStreamMessage(streamId, data, endStream);
        },
        
        close: (error) => {
          this.closed = true;
          if (this.pendingRead) {
            this.pendingRead(null);
            this.pendingRead = null;
          }
          this._sendStreamClose(streamId, error);
        }
      };
      
      this.streams.set(streamId, stream);
      
      // Send stream open
      this._send({
        type: 'stream_open',
        streamId,
        streamType: type,
        metadata,
        capability: this.capability
      });
      
      // Wait for ack
      this.once(`stream_ack_${streamId}`, (ack) => {
        if (ack.success) {
          resolve(stream);
        } else {
          this.streams.delete(streamId);
          reject(new Error(ack.error || 'Stream open failed'));
        }
      });
      
      // Timeout
      setTimeout(() => {
        if (this.streams.has(streamId)) {
          this.streams.delete(streamId);
          reject(new Error('Stream open timeout'));
        }
      }, 10000);
    });
  }
  
  /**
   * Open a server-streaming RPC
   */
  async *serverStream(method, payload) {
    const stream = await this.openStream('server', { method });
    await stream.write(payload, true);
    yield* stream;
  }
  
  /**
   * Open a bidirectional streaming RPC
   */
  async bidiStream(method) {
    const stream = await this.openStream('bidi', { method });
    return {
      write: (data) => stream.write(data),
      [Symbol.asyncIterator]: () => stream[Symbol.asyncIterator](),
      close: (error) => stream.close(error)
    };
  }
  
  _sendStreamMessage(streamId, data, endStream = false) {
    this._send({
      type: 'stream_message',
      streamId,
      message: JSON.stringify({
        streamId,
        type: 'data',
        payload: data,
        flags: endStream ? 1 : 0
      })
    });
  }
  
  _sendStreamClose(streamId, error) {
    this._send({
      type: 'stream_message',
      streamId,
      message: JSON.stringify({
        streamId,
        type: error ? 'error' : 'close',
        payload: error
      })
    });
  }
  
  // ─── Federation ────────────────────────────────────────────────────
  
  /**
   * Locate an agent in the federation
   */
  async locateAgent(agentId) {
    const res = await fetch(`${this.restUrl}/api/federation/agents/${agentId}`, {
      headers: { 'Authorization': `Bearer ${this.token}` }
    });
    if (!res.ok) throw new Error('Failed to locate agent');
    return res.json();
  }
  
  /**
   * List federation peers
   */
  async listPeers() {
    const res = await fetch(`${this.restUrl}/api/federation/peers`, {
      headers: { 'Authorization': `Bearer ${this.token}` }
    });
    if (!res.ok) throw new Error('Failed to list peers');
    return res.json();
  }
  
  /**
   * List federated sessions
   */
  async listFederatedSessions() {
    const res = await fetch(`${this.restUrl}/api/federation/sessions`, {
      headers: { 'Authorization': `Bearer ${this.token}` }
    });
    if (!res.ok) throw new Error('Failed to list federated sessions');
    return res.json();
  }
  
  // ─── Agent Registry ─────────────────────────────────────────────
  
  async listAgents() {
    const res = await fetch(`${this.restUrl}/api/agents`, {
      headers: { 'Authorization': `Bearer ${this.token}` }
    });
    if (!res.ok) throw new Error('Failed to list agents');
    return res.json();
  }
  
  async getAgent(agentId) {
    const res = await fetch(`${this.restUrl}/api/agents/${agentId}`, {
      headers: { 'Authorization': `Bearer ${this.token}` }
    });
    if (!res.ok) throw new Error('Failed to get agent');
    return res.json();
  }
  
  // ─── Event System ───────────────────────────────────────────────
  
  on(event, handler) {
    if (!this.eventHandlers.has(event)) {
      this.eventHandlers.set(event, new Set());
    }
    this.eventHandlers.get(event).add(handler);
  }
  
  once(event, handler) {
    const onceHandler = (...args) => {
      handler(...args);
      this.off(event, onceHandler);
    };
    this.on(event, onceHandler);
  }
  
  off(event, handler) {
    if (this.eventHandlers.has(event)) {
      this.eventHandlers.get(event).delete(handler);
    }
  }
  
  emit(event, ...args) {
    if (this.eventHandlers.has(event)) {
      for (const handler of this.eventHandlers.get(event)) {
        try { handler(...args); } catch (e) { console.error('Event handler error:', e); }
      }
    }
  }
  
  // ─── Disconnect ─────────────────────────────────────────────────
  
  disconnect() {
    this._clearHeartbeat();
    // Close all streams
    for (const stream of this.streams.values()) {
      stream.closed = true;
      if (stream.pendingRead) {
        stream.pendingRead(null);
        stream.pendingRead = null;
      }
    }
    this.streams.clear();
    
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.connected = false;
    this.authenticated = false;
  }
}

// ─── Convenience Factory ──────────────────────────────────────────

export async function createClient(options) {
  const client = new CoordinationClient(options);
  await client.connect(options);
  return client;
}

export default { CoordinationClient, createClient };