/**
 * Coordination Server Client SDK - TypeScript Definitions
 * 
 * Provides type-safe access to all coordination server features
 */

// ─── Core Types ──────────────────────────────────────────────────────

export interface AgentInfo {
  id: string;
  name: string;
  type: string;
  version: string;
  capabilities: string[];
  metadata: Record<string, unknown>;
  status: 'online' | 'offline';
  connectedAt: number;
  lastHeartbeat: number;
  subscriptions: string[];
}

export interface Session {
  id: string;
  owner: string;
  name: string;
  description: string;
  tags: string[];
  visibility: 'private' | 'shared' | 'public';
  participants: string[];
  messageCount: number;
  createdAt: number;
  updatedAt: number;
  metadata: Record<string, unknown>;
}

export interface SessionMessage {
  type: 'session_message';
  sessionId: string;
  from: string;
  payload: unknown;
  timestamp: number;
}

export interface DirectMessage {
  type: 'direct';
  from: string;
  payload: unknown;
  timestamp: number;
}

export interface BroadcastMessage {
  type: 'broadcast';
  from: string;
  payload: unknown;
  timestamp: number;
}

export interface AgentListMessage {
  type: 'agent_list';
  agents: AgentInfo[];
  timestamp: number;
}

export interface AuthResult {
  success: boolean;
  registered?: boolean;
  agentId?: string;
  reason?: string;
  message?: string;
}

export type IncomingMessage = 
  | AuthResult
  | SessionMessage
  | DirectMessage
  | BroadcastMessage
  | AgentListMessage
  | { type: 'participant_joined'; sessionId: string; agentId: string; agentName: string }
  | { type: 'participant_left'; sessionId: string; agentId: string }
  | { type: 'session_created'; session: Session }
  | { type: 'session_joined'; session: Session }
  | { type: 'error'; code: string; message: string }
  | { type: 'ping'; timestamp: number }
  | { type: 'ack'; id: number; success: boolean; [key: string]: unknown };

// ─── Capability Types ────────────────────────────────────────────────

export interface Caveat {
  type: 'time' | 'ip' | 'agent' | 'resource' | 'action' | 'delegation' | 'custom';
  condition: Record<string, unknown>;
  description?: string;
}

export interface CapabilityOptions {
  identifier: string;
  caveats?: Caveat[];
  ttl?: number;
  metadata?: Record<string, unknown>;
}

export interface DelegationOptions {
  parentCapability: string;
  identifier: string;
  caveats?: Caveat[];
  ttl?: number;
}

// ─── Stream Types ────────────────────────────────────────────────────

export type StreamType = 'request_response' | 'server_streaming' | 'client_streaming' | 'bidi_streaming' | 'pubsub' | 'event_source';

export interface StreamMetadata {
  type: StreamType;
  method?: string;
  channel?: string;
  subscribe?: boolean;
  publish?: boolean;
  [key: string]: unknown;
}

export interface StreamMessage<T = unknown> {
  streamId: string;
  type: 'data' | 'headers' | 'trailers' | 'close' | 'error';
  payload: T;
  headers?: Record<string, string>;
  flags?: number;
  timestamp: number;
  sequence: number;
}

export interface Stream<T = unknown> {
  streamId: string;
  type: StreamType;
  metadata: StreamMetadata;
  closed: boolean;
  
  write(data: T, endStream?: boolean): void;
  close(error?: Error): void;
  
  [Symbol.asyncIterator](): AsyncIterableIterator<T>;
}

// ─── Federation Types ────────────────────────────────────────────────

export interface FederationPeer {
  nodeId: string;
  status: 'online' | 'degraded' | 'offline';
  connectedAt: number;
  lastHeartbeat: number;
  info?: {
    nodeId: string;
    listenUrl: string;
    version: string;
    capabilities: string[];
  };
  load?: {
    agents: number;
    remoteAgents: number;
    peers: number;
    sessions: number;
    memory: number;
  };
}

export interface FederationAgentLocation {
  local: boolean;
  nodeId: string;
  info?: {
    nodeId: string;
    info: Record<string, unknown>;
    capabilities: string[];
    lastSeen: number;
  };
}

export interface FederatedSession {
  sessionId: string;
  owner: string;
  nodes: string[];
  participantCount: number;
  createdAt: number;
}

// ─── Client Options ──────────────────────────────────────────────────

export interface CoordinationClientOptions {
  serverUrl?: string;
  restUrl?: string;
  agentId?: string;
  name?: string;
  type?: string;
  version?: string;
  capabilities?: string[];
  metadata?: Record<string, unknown>;
  maxReconnectAttempts?: number;
  reconnectDelay?: number;
  requestTimeout?: number;
}

export interface ConnectOptions {
  agentId?: string;
  token?: string;
  secret?: string;
}

export interface ConnectWithCapabilityOptions {
  capability: string;
}

// ─── Event Types ─────────────────────────────────────────────────────

export interface ClientEvents {
  connect: () => void;
  disconnect: () => void;
  error: (error: Error) => void;
  auth_result: (result: AuthResult) => void;
  agent_list: (message: AgentListMessage) => void;
  direct: (message: DirectMessage) => void;
  broadcast: (message: BroadcastMessage) => void;
  session_message: (message: SessionMessage) => void;
  session_created: (message: { type: 'session_created'; session: Session }) => void;
  session_joined: (message: { type: 'session_joined'; session: Session }) => void;
  participant_joined: (message: { type: 'participant_joined'; sessionId: string; agentId: string; agentName: string }) => void;
  participant_left: (message: { type: 'participant_left'; sessionId: string; agentId: string }) => void;
  ping: (message: { type: 'ping'; timestamp: number }) => void;
  stream_data: (data: { streamId: string; payload: unknown }) => void;
  stream_close: (data: { streamId: string; error?: Error }) => void;
  [key: string]: (...args: unknown[]) => void;
}

// ─── Main Client Class ───────────────────────────────────────────────

export class CoordinationClient {
  constructor(options?: CoordinationClientOptions);
  
  // ─── Connection ─────────────────────────────────────────────────────
  
  /**
   * Connect using JWT token or secret
   */
  connect(authOptions: ConnectOptions): Promise<this>;
  
  /**
   * Connect using OCAP capability token
   */
  connectWithCapability(capability: string): Promise<this>;
  
  /**
   * Request a new capability from the server
   */
  requestCapability(options: CapabilityOptions): Promise<string>;
  
  /**
   * Delegate a capability to another agent
   */
  delegateCapability(options: DelegationOptions): Promise<string>;
  
  disconnect(): void;
  
  // ─── Session Management ────────────────────────────────────────────
  
  createSession(options?: Record<string, unknown>): Promise<Session>;
  joinSession(sessionId: string): Promise<boolean>;
  leaveSession(sessionId: string): Promise<boolean>;
  sendSessionMessage(sessionId: string, content: unknown): Promise<boolean>;
  getSessionMessages(sessionId: string, limit?: number, offset?: number): Promise<{ messages: SessionMessage[]; total: number }>;
  listSessions(filters?: { visibility?: string; participant?: string }): Promise<{ sessions: Session[] }>;
  
  // ─── Direct Messaging ──────────────────────────────────────────────
  
  sendDirectMessage(targetAgentId: string, payload: unknown): Promise<boolean>;
  broadcast(payload: unknown): Promise<{ success: boolean; recipients: number }>;
  
  // ─── Subscriptions ─────────────────────────────────────────────────
  
  subscribe(channel: string): Promise<boolean>;
  unsubscribe(channel: string): Promise<boolean>;
  
  // ─── Streaming ─────────────────────────────────────────────────────
  
  /**
   * Open a bidirectional stream
   */
  openStream<T = unknown>(type: StreamType, metadata?: StreamMetadata): Promise<Stream<T>>;
  
  /**
   * Open a server-streaming RPC
   */
  serverStream<T = unknown>(method: string, payload: unknown): AsyncIterableIterator<T>;
  
  /**
   * Open a bidirectional streaming RPC
   */
  bidiStream<T = unknown>(method: string): { 
    write: (data: T) => void; 
    [Symbol.asyncIterator](): AsyncIterableIterator<T>;
    close: (error?: Error) => void;
  };
  
  // ─── Federation ────────────────────────────────────────────────────
  
  locateAgent(agentId: string): Promise<FederationAgentLocation>;
  listPeers(): Promise<{ peers: FederationPeer[] }>;
  listFederatedSessions(): Promise<{ sessions: FederatedSession[] }>;
  
  // ─── Agent Registry ────────────────────────────────────────────────
  
  listAgents(): Promise<{ agents: AgentInfo[] }>;
  getAgent(agentId: string): Promise<AgentInfo>;
  
  // ─── Event System ──────────────────────────────────────────────────
  
  on<K extends keyof ClientEvents>(event: K, handler: ClientEvents[K]): void;
  once<K extends keyof ClientEvents>(event: K, handler: ClientEvents[K]): void;
  off<K extends keyof ClientEvents>(event: K, handler: ClientEvents[K]): void;
  emit(event: string, ...args: unknown[]): void;
}

// ─── Factory ─────────────────────────────────────────────────────────

export function createClient(options: CoordinationClientOptions): Promise<CoordinationClient>;

export default { CoordinationClient, createClient };