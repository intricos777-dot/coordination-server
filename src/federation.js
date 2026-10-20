// Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
/**
 * Federation Protocol for Cross-Node Agent Communication
 * 
 * Enables secure agent-to-agent communication across multiple
 * coordination server instances (federated deployment)
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { Capability, CapabilityStore } from './capabilities.js';

// ─── Protocol Constants ─────────────────────────────────────────────

const PROTOCOL_VERSION = 'federation-v1';
const MESSAGE_TYPES = {
  // Federation management
  NODE_ANNOUNCE: 'node_announce',
  NODE_HEARTBEAT: 'node_heartbeat',
  NODE_LEAVE: 'node_leave',
  NODE_LIST: 'node_list',
  
  // Agent routing
  AGENT_REGISTER: 'agent_register',
  AGENT_UNREGISTER: 'agent_unregister',
  AGENT_LOOKUP: 'agent_lookup',
  AGENT_ROUTE: 'agent_route',
  
  // Message forwarding
  FORWARD_DIRECT: 'forward_direct',
  FORWARD_BROADCAST: 'forward_broadcast',
  FORWARD_SESSION: 'forward_session',
  
  // Session federation
  SESSION_CREATE: 'session_create',
  SESSION_JOIN: 'session_join',
  SESSION_LEAVE: 'session_leave',
  SESSION_SYNC: 'session_sync',
  
  // Capability verification
  CAPABILITY_VERIFY: 'capability_verify',
  CAPABILITY_DELEGATE: 'capability_delegate',
  
  // Stream federation
  STREAM_OPEN: 'stream_open',
  STREAM_DATA: 'stream_data',
  STREAM_CLOSE: 'stream_close',
  
  // Control
  PING: 'ping',
  PONG: 'pong',
  ERROR: 'error',
  ACK: 'ack'
};

const NODE_STATUS = {
  ONLINE: 'online',
  DEGRADED: 'degraded',
  OFFLINE: 'offline'
};

// ─── Federation Node ────────────────────────────────────────────────

export class FederationNode extends EventEmitter {
  /**
   * @param {Object} opts
   * @param {string} opts.nodeId - Unique node identifier
   * @param {string} opts.listenUrl - URL this node listens on (for other nodes)
   * @param {CapabilityStore} opts.capabilityStore - Capability store for auth
   * @param {Object} [opts.logger] - Logger instance
   */
  constructor({ nodeId, listenUrl, capabilityStore, logger = console }) {
    super();
    this.nodeId = nodeId;
    this.listenUrl = listenUrl;
    this.capabilityStore = capabilityStore;
    this.logger = logger;
    
    // Peer nodes: nodeId -> { info, ws, lastHeartbeat, status }
    this.peers = new Map();
    
    // Local agent registry: agentId -> { nodeId, info, capabilities }
    this.localAgents = new Map();
    
    // Remote agent registry: agentId -> { nodeId, info, lastSeen }
    this.remoteAgents = new Map();
    
    // Pending requests: requestId -> { resolve, reject, timeout }
    this.pendingRequests = new Map();
    
    // Message routing table: messageId -> { fromNode, fromAgent, timestamp }
    this.messageRoutes = new Map();
    
    // Session federation state: sessionId -> { nodes: Set, participants: Map }
    this.federatedSessions = new Map();
    
    // Stream federation: streamId -> { nodes, participants }
    this.federatedStreams = new Map();
    
    this.heartbeatInterval = null;
    this.cleanupInterval = null;
    this.started = false;
  }

  // ─── Lifecycle ────────────────────────────────────────────────────

  async start() {
    if (this.started) return;
    this.started = true;
    
    // Start heartbeat to peers
    this.heartbeatInterval = setInterval(() => this._sendHeartbeats(), 30000);
    
    // Cleanup stale peers
    this.cleanupInterval = setInterval(() => this._cleanupPeers(), 60000);
    
    this.emit('started');
    this.logger.info(`Federation node ${this.nodeId} started`);
  }

  async stop() {
    if (!this.started) return;
    this.started = false;
    
    if (this.heartbeatInterval) clearInterval(this.heartbeatInterval);
    if (this.cleanupInterval) clearInterval(this.cleanupInterval);
    
    // Notify peers we're leaving
    await this._broadcastToPeers({
      type: MESSAGE_TYPES.NODE_LEAVE,
      nodeId: this.nodeId,
      timestamp: Date.now()
    });
    
    // Close all peer connections
    for (const [peerId, peer] of this.peers.entries()) {
      if (peer.ws) peer.ws.close();
    }
    this.peers.clear();
    
    this.emit('stopped');
    this.logger.info(`Federation node ${this.nodeId} stopped`);
  }

  // ─── Peer Management ──────────────────────────────────────────────

  /**
   * Connect to a peer node
   * @param {string} peerUrl - Peer's WebSocket URL
   * @param {Capability} capability - Capability for peer authentication
   * @returns {Promise<boolean>}
   */
  async connectToPeer(peerUrl, capability) {
    // This would establish a WebSocket connection to the peer
    // For now, we simulate with in-memory (real impl needs ws client)
    this.logger.info(`Connecting to peer at ${peerUrl}`);
    
    // In real implementation:
    // const ws = new WebSocket(peerUrl);
    // ws.onopen = () => this._handlePeerConnection(ws, capability);
    // ws.onmessage = (msg) => this._handlePeerMessage(ws, msg);
    
    return true;
  }

  /**
   * Accept incoming peer connection
   * @param {WebSocket} ws - WebSocket connection
   * @param {Capability} capability - Peer's capability
   */
  async acceptPeer(ws, capability) {
    // Verify peer's capability
    const auth = await this.capabilityStore.authorize(
      capability.serialize(),
      { agentId: capability.identifier, resource: 'federation:peer', action: 'connect' }
    );
    
    if (!auth.valid) {
      ws.close(4001, 'Invalid capability');
      return;
    }
    
    const peerId = capability.identifier;
    const peer = {
      id: peerId,
      ws,
      connectedAt: Date.now(),
      lastHeartbeat: Date.now(),
      status: NODE_STATUS.ONLINE,
      info: null
    };
    
    this.peers.set(peerId, peer);
    
    ws.on('message', (data) => this._handlePeerMessage(peerId, data));
    ws.on('close', () => this._handlePeerDisconnect(peerId));
    ws.on('error', (err) => this.logger.error(`Peer ${peerId} error`, err));
    
    // Send our node info
    this._sendToPeer(peerId, {
      type: MESSAGE_TYPES.NODE_ANNOUNCE,
      nodeId: this.nodeId,
      listenUrl: this.listenUrl,
      timestamp: Date.now()
    });
    
    this.emit('peerConnected', peerId);
    this.logger.info(`Peer connected: ${peerId}`);
  }

  _handlePeerMessage(peerId, data) {
    try {
      const message = JSON.parse(data.toString());
      this._routePeerMessage(peerId, message);
    } catch (e) {
      this.logger.error(`Invalid message from peer ${peerId}`, e);
    }
  }

  _handlePeerDisconnect(peerId) {
    const peer = this.peers.get(peerId);
    if (peer) {
      peer.status = NODE_STATUS.OFFLINE;
      // Don't remove immediately - allow reconnection
      setTimeout(() => {
        const p = this.peers.get(peerId);
        if (p && p.status === NODE_STATUS.OFFLINE) {
          this.peers.delete(peerId);
          this._handlePeerLeave(peerId);
        }
      }, 120000); // 2 min grace period
    }
  }

  _handlePeerLeave(peerId) {
    // Clean up remote agents from this peer
    for (const [agentId, agent] of this.remoteAgents.entries()) {
      if (agent.nodeId === peerId) {
        this.remoteAgents.delete(agentId);
        this.emit('agentLeft', agentId, peerId);
      }
    }
    
    // Clean up federated sessions
    for (const [sessionId, session] of this.federatedSessions.entries()) {
      session.nodes.delete(peerId);
      if (session.nodes.size === 0) {
        this.federatedSessions.delete(sessionId);
      }
    }
    
    this.emit('peerDisconnected', peerId);
    this.logger.info(`Peer disconnected: ${peerId}`);
  }

  // ─── Message Routing ──────────────────────────────────────────────

  _routePeerMessage(fromNodeId, message) {
    const { type } = message;
    
    switch (type) {
      case MESSAGE_TYPES.NODE_ANNOUNCE:
        this._handleNodeAnnounce(fromNodeId, message);
        break;
      case MESSAGE_TYPES.NODE_HEARTBEAT:
        this._handleNodeHeartbeat(fromNodeId, message);
        break;
      case MESSAGE_TYPES.NODE_LEAVE:
        this._handlePeerLeave(fromNodeId);
        break;
      case MESSAGE_TYPES.AGENT_REGISTER:
        this._handleAgentRegister(fromNodeId, message);
        break;
      case MESSAGE_TYPES.AGENT_UNREGISTER:
        this._handleAgentUnregister(fromNodeId, message);
        break;
      case MESSAGE_TYPES.AGENT_LOOKUP:
        this._handleAgentLookup(fromNodeId, message);
        break;
      case MESSAGE_TYPES.AGENT_ROUTE:
        this._handleAgentRoute(fromNodeId, message);
        break;
      case MESSAGE_TYPES.FORWARD_DIRECT:
        this._handleForwardDirect(fromNodeId, message);
        break;
      case MESSAGE_TYPES.FORWARD_BROADCAST:
        this._handleForwardBroadcast(fromNodeId, message);
        break;
      case MESSAGE_TYPES.FORWARD_SESSION:
        this._handleForwardSession(fromNodeId, message);
        break;
      case MESSAGE_TYPES.SESSION_CREATE:
      case MESSAGE_TYPES.SESSION_JOIN:
      case MESSAGE_TYPES.SESSION_LEAVE:
      case MESSAGE_TYPES.SESSION_SYNC:
        this._handleSessionFederation(fromNodeId, message);
        break;
      case MESSAGE_TYPES.CAPABILITY_VERIFY:
        this._handleCapabilityVerify(fromNodeId, message);
        break;
      case MESSAGE_TYPES.STREAM_OPEN:
      case MESSAGE_TYPES.STREAM_DATA:
      case MESSAGE_TYPES.STREAM_CLOSE:
        this._handleStreamFederation(fromNodeId, message);
        break;
      case MESSAGE_TYPES.PING:
        this._sendToPeer(fromNodeId, { type: MESSAGE_TYPES.PONG, timestamp: Date.now() });
        break;
      case MESSAGE_TYPES.ACK:
        this._handleAck(message);
        break;
      case MESSAGE_TYPES.ERROR:
        this.logger.error(`Peer ${fromNodeId} error:`, message.error);
        break;
      default:
        this.logger.warn(`Unknown message type from peer ${fromNodeId}: ${type}`);
    }
  }

  // ─── Node Announcement ────────────────────────────────────────────

  _handleNodeAnnounce(fromNodeId, message) {
    const peer = this.peers.get(fromNodeId);
    if (peer) {
      peer.info = {
        nodeId: message.nodeId,
        listenUrl: message.listenUrl,
        version: message.version,
        capabilities: message.capabilities || []
      };
      peer.status = NODE_STATUS.ONLINE;
      peer.lastHeartbeat = Date.now();
    }
    this.emit('nodeAnnounced', message.nodeId, message);
  }

  _handleNodeHeartbeat(fromNodeId, message) {
    const peer = this.peers.get(fromNodeId);
    if (peer) {
      peer.lastHeartbeat = Date.now();
      peer.status = NODE_STATUS.ONLINE;
      if (message.load !== undefined) peer.load = message.load;
    }
  }

  _sendHeartbeats() {
    const message = {
      type: MESSAGE_TYPES.NODE_HEARTBEAT,
      nodeId: this.nodeId,
      timestamp: Date.now(),
      load: this._getLoadInfo()
    };
    this._broadcastToPeers(message);
  }

  _getLoadInfo() {
    return {
      agents: this.localAgents.size,
      remoteAgents: this.remoteAgents.size,
      peers: this.peers.size,
      sessions: this.federatedSessions.size,
      memory: process.memoryUsage().heapUsed
    };
  }

  _cleanupPeers() {
    const now = Date.now();
    for (const [peerId, peer] of this.peers.entries()) {
      if (now - peer.lastHeartbeat > 120000) { // 2 min timeout
        if (peer.status !== NODE_STATUS.OFFLINE) {
          peer.status = NODE_STATUS.OFFLINE;
          this._handlePeerLeave(peerId);
        }
      } else if (now - peer.lastHeartbeat > 60000) {
        peer.status = NODE_STATUS.DEGRADED;
      }
    }
  }

  // ─── Agent Registration ───────────────────────────────────────────

  /**
   * Register a local agent with federation
   * @param {string} agentId
   * @param {Object} info - Agent info
   * @param {string[]} capabilities - Agent capabilities
   */
  registerLocalAgent(agentId, info, capabilities = []) {
    this.localAgents.set(agentId, {
      nodeId: this.nodeId,
      info,
      capabilities,
      registeredAt: Date.now()
    });
    
    // Announce to peers
    this._broadcastToPeers({
      type: MESSAGE_TYPES.AGENT_REGISTER,
      nodeId: this.nodeId,
      agentId,
      info,
      capabilities,
      timestamp: Date.now()
    });
    
    this.emit('localAgentRegistered', agentId);
  }

  /**
   * Unregister a local agent
   * @param {string} agentId
   */
  unregisterLocalAgent(agentId) {
    this.localAgents.delete(agentId);
    
    this._broadcastToPeers({
      type: MESSAGE_TYPES.AGENT_UNREGISTER,
      nodeId: this.nodeId,
      agentId,
      timestamp: Date.now()
    });
    
    this.emit('localAgentUnregistered', agentId);
  }

  _handleAgentRegister(fromNodeId, message) {
    const { agentId, info, capabilities } = message;
    this.remoteAgents.set(agentId, {
      nodeId: fromNodeId,
      info,
      capabilities,
      lastSeen: Date.now()
    });
    this.emit('remoteAgentRegistered', agentId, fromNodeId);
  }

  _handleAgentUnregister(fromNodeId, message) {
    const { agentId } = message;
    const agent = this.remoteAgents.get(agentId);
    if (agent && agent.nodeId === fromNodeId) {
      this.remoteAgents.delete(agentId);
      this.emit('remoteAgentUnregistered', agentId, fromNodeId);
    }
  }

  // ─── Agent Lookup & Routing ───────────────────────────────────────

  /**
   * Find agent location (local or remote)
   * @param {string} agentId
   * @returns {{ local: boolean, nodeId: string, info?: Object } | null}
   */
  locateAgent(agentId) {
    if (this.localAgents.has(agentId)) {
      return { local: true, nodeId: this.nodeId, info: this.localAgents.get(agentId) };
    }
    const remote = this.remoteAgents.get(agentId);
    if (remote) {
      return { local: false, nodeId: remote.nodeId, info: remote };
    }
    return null;
  }

  /**
   * Route a message to an agent (local or remote)
   * @param {string} fromAgentId
   * @param {string} toAgentId
   * @param {Object} payload
   * @param {Capability} capability - Sender's capability
   * @returns {Promise<Object>}
   */
  async routeMessage(fromAgentId, toAgentId, payload, capability) {
    const location = this.locateAgent(toAgentId);
    
    if (!location) {
      return { success: false, reason: 'Agent not found' };
    }
    
    if (location.local) {
      // Local delivery - emit for local handler
      this.emit('localMessage', { from: fromAgentId, to: toAgentId, payload });
      return { success: true, local: true };
    }
    
    // Remote delivery
    const messageId = uuidv4();
    this.messageRoutes.set(messageId, {
      fromNode: this.nodeId,
      fromAgent: fromAgentId,
      toAgent: toAgentId,
      timestamp: Date.now()
    });
    
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(messageId);
        this.messageRoutes.delete(messageId);
        reject(new Error('Routing timeout'));
      }, 30000);
      
      this.pendingRequests.set(messageId, { resolve, reject, timeout });
      
      this._sendToPeer(location.nodeId, {
        type: MESSAGE_TYPES.FORWARD_DIRECT,
        messageId,
        fromNode: this.nodeId,
        fromAgent: fromAgentId,
        toAgent: toAgentId,
        payload,
        capability: capability.serialize(),
        timestamp: Date.now()
      });
    });
  }

  _handleAgentRoute(fromNodeId, message) {
    const { messageId, fromAgent, toAgent, payload, capability } = message;
    
    // Verify capability
    this.capabilityStore.authorize(capability, {
      agentId: fromAgent,
      resource: `agent:${toAgent}`,
      action: 'invoke'
    }).then(auth => {
      if (!auth.valid) {
        this._sendToPeer(fromNodeId, {
          type: MESSAGE_TYPES.ERROR,
          messageId,
          error: `Capability verification failed: ${auth.reason}`,
          timestamp: Date.now()
        });
        return;
      }
      
      // Deliver locally
      this.emit('localMessage', { from: fromAgent, to: toAgent, payload });
      
      // Acknowledge
      this._sendToPeer(fromNodeId, {
        type: MESSAGE_TYPES.ACK,
        messageId,
        success: true,
        timestamp: Date.now()
      });
    });
  }

  _handleForwardDirect(fromNodeId, message) {
    // This node is the target - deliver to local agent
    const { messageId, fromAgent, toAgent, payload, capability } = message;
    
    // Verify capability
    this.capabilityStore.authorize(capability, {
      agentId: fromAgent,
      resource: `agent:${toAgent}`,
      action: 'invoke'
    }).then(auth => {
      if (auth.valid) {
        this.emit('localMessage', { from: fromAgent, to: toAgent, payload });
      }
      
      // Send ACK back
      this._sendToPeer(fromNodeId, {
        type: MESSAGE_TYPES.ACK,
        messageId,
        success: auth.valid,
        reason: auth.reason,
        timestamp: Date.now()
      });
    });
  }

  _handleAck(message) {
    const { messageId, success, reason } = message;
    const pending = this.pendingRequests.get(messageId);
    if (pending) {
      clearTimeout(pending.timeout);
      this.pendingRequests.delete(messageId);
      this.messageRoutes.delete(messageId);
      if (success) pending.resolve({ success: true });
      else pending.reject(new Error(reason || 'Remote delivery failed'));
    }
  }

  // ─── Broadcast ────────────────────────────────────────────────────

  /**
   * Broadcast to all agents (local + remote)
   * @param {string} fromAgentId
   * @param {Object} payload
   * @param {Capability} capability
   * @returns {Promise<Object>}
   */
  async broadcast(fromAgentId, payload, capability) {
    // Local broadcast
    this.emit('localBroadcast', { from: fromAgentId, payload });
    
    // Remote broadcast
    await this._broadcastToPeers({
      type: MESSAGE_TYPES.FORWARD_BROADCAST,
      fromNode: this.nodeId,
      fromAgent: fromAgentId,
      payload,
      capability: capability.serialize(),
      timestamp: Date.now()
    });
    
    return { success: true };
  }

  _handleForwardBroadcast(fromNodeId, message) {
    const { fromAgent, payload, capability } = message;
    
    this.capabilityStore.authorize(capability, {
      agentId: fromAgent,
      resource: 'broadcast',
      action: 'send'
    }).then(auth => {
      if (auth.valid) {
        this.emit('localBroadcast', { from: fromAgent, payload });
      }
    });
  }

  // ─── Session Federation ───────────────────────────────────────────

  /**
   * Create a federated session
   * @param {string} ownerAgentId
   * @param {Object} metadata
   * @returns {Promise<string>} sessionId
   */
  async createFederatedSession(ownerAgentId, metadata = {}) {
    const sessionId = uuidv4();
    
    this.federatedSessions.set(sessionId, {
      id: sessionId,
      owner: ownerAgentId,
      nodes: new Set([this.nodeId]),
      participants: new Map([[ownerAgentId, { nodeId: this.nodeId, ...metadata }]]),
      createdAt: Date.now(),
      metadata
    });
    
    // Announce to peers
    await this._broadcastToPeers({
      type: MESSAGE_TYPES.SESSION_CREATE,
      sessionId,
      owner: ownerAgentId,
      metadata,
      timestamp: Date.now()
    });
    
    return sessionId;
  }

  /**
   * Join a federated session
   * @param {string} sessionId
   * @param {string} agentId
   * @returns {Promise<boolean>}
   */
  async joinFederatedSession(sessionId, agentId) {
    const session = this.federatedSessions.get(sessionId);
    if (!session) return false;
    
    const location = this.locateAgent(agentId);
    const nodeId = location?.nodeId || this.nodeId;
    
    session.participants.set(agentId, { nodeId, joinedAt: Date.now() });
    session.nodes.add(nodeId);
    
    // Notify other nodes
    await this._broadcastToPeers({
      type: MESSAGE_TYPES.SESSION_JOIN,
      sessionId,
      agentId,
      nodeId,
      timestamp: Date.now()
    }, nodeId); // Exclude the node where agent resides
    
    return true;
  }

  _handleSessionFederation(fromNodeId, message) {
    const { type, sessionId } = message;
    let session = this.federatedSessions.get(sessionId);
    
    switch (type) {
      case MESSAGE_TYPES.SESSION_CREATE:
        if (!session) {
          session = {
            id: sessionId,
            owner: message.owner,
            nodes: new Set([fromNodeId, this.nodeId]),
            participants: new Map([[message.owner, { nodeId: fromNodeId }]]),
            createdAt: message.timestamp,
            metadata: message.metadata
          };
          this.federatedSessions.set(sessionId, session);
        }
        break;
        
      case MESSAGE_TYPES.SESSION_JOIN:
        if (session) {
          session.participants.set(message.agentId, { 
            nodeId: message.nodeId, 
            joinedAt: message.timestamp 
          });
          session.nodes.add(message.nodeId);
        }
        break;
        
      case MESSAGE_TYPES.SESSION_LEAVE:
        if (session) {
          session.participants.delete(message.agentId);
          // Check if node still has participants
          const nodeHasParticipants = Array.from(session.participants.values())
            .some(p => p.nodeId === fromNodeId);
          if (!nodeHasParticipants) {
            session.nodes.delete(fromNodeId);
          }
        }
        break;
        
      case MESSAGE_TYPES.SESSION_SYNC:
        // Full state sync
        if (session && message.state) {
          session.participants = new Map(Object.entries(message.state.participants));
          session.nodes = new Set(message.state.nodes);
        }
        break;
    }
  }

  // ─── Stream Federation ────────────────────────────────────────────

  /**
   * Open a federated stream
   * @param {string} streamId
   * @param {string} ownerAgentId
   * @param {Object} metadata
   */
  openFederatedStream(streamId, ownerAgentId, metadata = {}) {
    this.federatedStreams.set(streamId, {
      id: streamId,
      owner: ownerAgentId,
      nodes: new Set([this.nodeId]),
      participants: new Map([[ownerAgentId, { nodeId: this.nodeId }]]),
      metadata,
      createdAt: Date.now()
    });
    
    this._broadcastToPeers({
      type: MESSAGE_TYPES.STREAM_OPEN,
      streamId,
      owner: ownerAgentId,
      metadata,
      timestamp: Date.now()
    });
  }

  /**
   * Send data on a federated stream
   * @param {string} streamId
   * @param {string} fromAgentId
   * @param {*} data
   */
  sendStreamData(streamId, fromAgentId, data) {
    const stream = this.federatedStreams.get(streamId);
    if (!stream) return false;
    
    this._broadcastToPeers({
      type: MESSAGE_TYPES.STREAM_DATA,
      streamId,
      fromAgent: fromAgentId,
      data,
      timestamp: Date.now()
    });
    
    // Local delivery
    this.emit('streamData', { streamId, from: fromAgentId, data });
    return true;
  }

  _handleStreamFederation(fromNodeId, message) {
    const { type, streamId } = message;
    let stream = this.federatedStreams.get(streamId);
    
    switch (type) {
      case MESSAGE_TYPES.STREAM_OPEN:
        if (!stream) {
          stream = {
            id: streamId,
            owner: message.owner,
            nodes: new Set([fromNodeId, this.nodeId]),
            participants: new Map([[message.owner, { nodeId: fromNodeId }]]),
            metadata: message.metadata,
            createdAt: message.timestamp
          };
          this.federatedStreams.set(streamId, stream);
        }
        break;
        
      case MESSAGE_TYPES.STREAM_DATA:
        if (stream) {
          this.emit('streamData', { 
            streamId, 
            from: message.fromAgent, 
            data: message.data 
          });
        }
        break;
        
      case MESSAGE_TYPES.STREAM_CLOSE:
        if (stream) {
          stream.nodes.delete(fromNodeId);
          if (stream.nodes.size === 0) {
            this.federatedStreams.delete(streamId);
          }
        }
        break;
    }
  }

  // ─── Capability Verification ──────────────────────────────────────

  _handleCapabilityVerify(fromNodeId, message) {
    const { requestId, capability, context } = message;
    
    this.capabilityStore.authorize(capability, context).then(result => {
      this._sendToPeer(fromNodeId, {
        type: MESSAGE_TYPES.ACK,
        requestId,
        success: result.valid,
        reason: result.reason,
        capability: result.capability?.serialize(),
        timestamp: Date.now()
      });
    });
  }

  /**
   * Verify a capability across federation
   * @param {string} capabilityToken
   * @param {Object} context
   * @returns {Promise<Object>}
   */
  async verifyCapability(capabilityToken, context) {
    // Try local first
    const localResult = await this.capabilityStore.authorize(capabilityToken, context);
    if (localResult.valid) return localResult;
    
    // Could forward to other nodes for verification if needed
    return localResult;
  }

  // ─── Utility ──────────────────────────────────────────────────────

  _sendToPeer(peerId, message) {
    const peer = this.peers.get(peerId);
    if (peer && peer.ws && peer.ws.readyState === 1) {
      try {
        peer.ws.send(JSON.stringify(message));
        return true;
      } catch (e) {
        this.logger.error(`Failed to send to peer ${peerId}`, e);
      }
    }
    return false;
  }

  async _broadcastToPeers(message, excludeNodeId = null) {
    const promises = [];
    for (const [peerId, peer] of this.peers.entries()) {
      if (peerId !== excludeNodeId && peer.status === NODE_STATUS.ONLINE) {
        promises.push(this._sendToPeer(peerId, message));
      }
    }
    await Promise.all(promises);
  }

  // ─── Query Methods ────────────────────────────────────────────────

  getPeers() {
    return Array.from(this.peers.entries()).map(([id, peer]) => ({
      nodeId: id,
      status: peer.status,
      connectedAt: peer.connectedAt,
      lastHeartbeat: peer.lastHeartbeat,
      info: peer.info,
      load: peer.load
    }));
  }

  getLocalAgents() {
    return Array.from(this.localAgents.entries()).map(([id, agent]) => ({
      agentId: id,
      ...agent
    }));
  }

  getRemoteAgents() {
    return Array.from(this.remoteAgents.entries()).map(([id, agent]) => ({
      agentId: id,
      ...agent
    }));
  }

  getFederatedSessions() {
    return Array.from(this.federatedSessions.entries()).map(([id, session]) => ({
      sessionId: id,
      owner: session.owner,
      nodes: Array.from(session.nodes),
      participantCount: session.participants.size,
      createdAt: session.createdAt
    }));
  }

  getFederatedStreams() {
    return Array.from(this.federatedStreams.entries()).map(([id, stream]) => ({
      streamId: id,
      owner: stream.owner,
      nodes: Array.from(stream.nodes),
      participantCount: stream.participants.size
    }));
  }
}

// ─── Federation Client (for agents to use federation) ───────────────

export class FederationClient {
  constructor(federationNode) {
    this.node = federationNode;
  }

  /**
   * Send message to any agent in federation
   */
  async send(toAgentId, payload, capability) {
    return this.node.routeMessage(capability.identifier, toAgentId, payload, capability);
  }

  /**
   * Broadcast to all agents in federation
   */
  async broadcast(payload, capability) {
    return this.node.broadcast(capability.identifier, payload, capability);
  }

  /**
   * Create federated session
   */
  async createSession(metadata, capability) {
    return this.node.createFederatedSession(capability.identifier, metadata);
  }

  /**
   * Join federated session
   */
  async joinSession(sessionId, capability) {
    return this.node.joinFederatedSession(sessionId, capability.identifier);
  }

  /**
   * Open federated stream
   */
  openStream(streamId, metadata, capability) {
    return this.node.openFederatedStream(streamId, capability.identifier, metadata);
  }

  /**
   * Send stream data
   */
  sendStreamData(streamId, data, capability) {
    return this.node.sendStreamData(streamId, capability.identifier, data);
  }

  /**
   * Locate agent
   */
  locateAgent(agentId) {
    return this.node.locateAgent(agentId);
  }
}

export default { FederationNode, FederationClient, MESSAGE_TYPES, NODE_STATUS, PROTOCOL_VERSION };