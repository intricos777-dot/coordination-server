/**
 * Streaming Transport Layer
 * 
 * Supports:
 * - WebSocket streaming (current)
 * - gRPC-style bidirectional streaming
 * - QUIC/WebTransport (future)
 * - Server-Sent Events (SSE) fallback
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';

// ─── Stream Types ───────────────────────────────────────────────────

export const StreamType = {
  REQUEST_RESPONSE: 'request_response',     // Unary RPC
  SERVER_STREAMING: 'server_streaming',     // Server -> client stream
  CLIENT_STREAMING: 'client_streaming',     // Client -> server stream
  BIDI_STREAMING: 'bidi_streaming',         // Bidirectional stream
  PUBSUB: 'pubsub',                         // Pub/Sub channel
  EVENT_SOURCE: 'event_source'              // SSE
};

export const StreamState = {
  OPENING: 'opening',
  OPEN: 'open',
  HALF_CLOSED_LOCAL: 'half_closed_local',
  HALF_CLOSED_REMOTE: 'half_closed_remote',
  CLOSED: 'closed',
  ERROR: 'error'
};

// ─── Stream Message ─────────────────────────────────────────────────

export class StreamMessage {
  constructor({ streamId, type, payload, headers = {}, flags = 0 }) {
    this.streamId = streamId;
    this.type = type;           // 'data', 'headers', 'trailers', 'close', 'error'
    this.payload = payload;
    this.headers = headers;
    this.flags = flags;         // Bitmask: 1=END_STREAM, 2=END_HEADERS, 4=PRIORITY
    this.timestamp = Date.now();
    this.sequence = 0;
  }

  static data(streamId, payload, headers = {}) {
    return new StreamMessage({ streamId, type: 'data', payload, headers });
  }

  static headers(streamId, headers, endStream = false) {
    return new StreamMessage({ 
      streamId, 
      type: 'headers', 
      headers, 
      flags: endStream ? 1 : 0 
    });
  }

  static close(streamId, error = null) {
    return new StreamMessage({ 
      streamId, 
      type: error ? 'error' : 'close', 
      payload: error,
      flags: 1 
    });
  }

  serialize() {
    return JSON.stringify({
      streamId: this.streamId,
      type: this.type,
      payload: this.payload,
      headers: this.headers,
      flags: this.flags,
      timestamp: this.timestamp,
      sequence: this.sequence
    });
  }

  static deserialize(data) {
    const msg = JSON.parse(data);
    const streamMsg = new StreamMessage(msg);
    streamMsg.sequence = msg.sequence || 0;
    return streamMsg;
  }
}

// ─── Stream Interface ───────────────────────────────────────────────

export class Stream extends EventEmitter {
  constructor({ streamId, transport, initiator, metadata = {} }) {
    super();
    this.streamId = streamId;
    this.transport = transport;
    this.initiator = initiator;  // 'local' or 'remote'
    this.metadata = metadata;
    this.state = StreamState.OPENING;
    this.localClosed = false;
    this.remoteClosed = false;
    this.sendBuffer = [];
    this.receiveBuffer = [];
    this.flowControlWindow = 65536; // 64KB default
    this.pendingRead = null;
  }

  // ─── Sending ──────────────────────────────────────────────────────

  /**
   * Write data to stream
   * @param {*} data - Data to send
   * @param {Object} [headers] - Optional headers
   * @param {boolean} [endStream=false] - Close stream after this
   * @returns {Promise<boolean>}
   */
  async write(data, headers = {}, endStream = false) {
    if (this.state === StreamState.CLOSED || this.state === StreamState.ERROR) {
      throw new Error(`Stream ${this.streamId} is closed`);
    }
    if (this.localClosed) {
      throw new Error('Stream already closed locally');
    }

    const message = StreamMessage.data(this.streamId, data, headers);
    if (endStream) {
      message.flags |= 1; // END_STREAM
      this.localClosed = true;
    }

    return this.transport._sendStreamMessage(message);
  }

  /**
   * Send headers (for trailers or initial headers)
   * @param {Object} headers
   * @param {boolean} [endStream=false]
   */
  async sendHeaders(headers, endStream = false) {
    const message = StreamMessage.headers(this.streamId, headers, endStream);
    if (endStream) this.localClosed = true;
    return this.transport._sendStreamMessage(message);
  }

  /**
   * Close the stream gracefully
   * @param {Error} [error] - Optional error
   */
  async close(error = null) {
    if (this.state === StreamState.CLOSED) return;
    
    this.state = StreamState.CLOSED;
    this.localClosed = true;
    
    const message = StreamMessage.close(this.streamId, error);
    await this.transport._sendStreamMessage(message);
    
    this.emit('close', error);
    this.transport._removeStream(this.streamId);
  }

  // ─── Receiving ────────────────────────────────────────────────────

  /**
   * Read next message from stream (async iterator compatible)
   * @returns {Promise<StreamMessage|null>}
   */
  async read() {
    if (this.receiveBuffer.length > 0) {
      return this.receiveBuffer.shift();
    }

    if (this.state === StreamState.CLOSED || this.remoteClosed) {
      return null;
    }

    return new Promise((resolve) => {
      this.pendingRead = resolve;
    });
  }

  /**
   * Async iterator for stream data
   */
  async *[Symbol.asyncIterator]() {
    while (true) {
      const msg = await this.read();
      if (!msg) break;
      if (msg.type === 'data') yield msg.payload;
      if (msg.type === 'error') throw msg.payload;
    }
  }

  // ─── Internal ─────────────────────────────────────────────────────

  _receive(message) {
    if (message.type === 'data') {
      this.receiveBuffer.push(message);
      if (this.pendingRead) {
        this.pendingRead(this.receiveBuffer.shift());
        this.pendingRead = null;
      }
      this.emit('data', message.payload);
    } else if (message.type === 'close') {
      this.remoteClosed = true;
      this.state = StreamState.CLOSED;
      this.emit('close', null);
      if (this.pendingRead) {
        this.pendingRead(null);
        this.pendingRead = null;
      }
    } else if (message.type === 'error') {
      this.state = StreamState.ERROR;
      this.remoteClosed = true;
      this.emit('error', message.payload);
      if (this.pendingRead) {
        this.pendingRead(null);
        this.pendingRead = null;
      }
    }
  }

  _setState(state) {
    this.state = state;
    this.emit('stateChange', state);
  }
}

// ─── Transport Base Class ───────────────────────────────────────────

export class Transport extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = options;
    this.streams = new Map(); // streamId -> Stream
    this.pendingStreams = new Map(); // streamId -> { resolve, reject, timeout }
    this.messageId = 0;
  }

  // ─── Stream Management ────────────────────────────────────────────

  /**
   * Open a new stream
   * @param {Object} options
   * @param {string} options.type - Stream type
   * @param {Object} [options.metadata] - Stream metadata
   * @param {Capability} [options.capability] - Authorization capability
   * @returns {Promise<Stream>}
   */
  async openStream({ type = StreamType.BIDI_STREAMING, metadata = {}, capability = null }) {
    const streamId = uuidv4();
    const stream = new Stream({
      streamId,
      transport: this,
      initiator: 'local',
      metadata: { type, ...metadata }
    });

    this.streams.set(streamId, stream);

    // Send stream open message
    await this._sendStreamOpen(streamId, type, metadata, capability);

    // Wait for remote acknowledgment
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingStreams.delete(streamId);
        this.streams.delete(streamId);
        reject(new Error('Stream open timeout'));
      }, 10000);

      this.pendingStreams.set(streamId, { resolve, reject, timeout });

      stream.once('stateChange', (state) => {
        if (state === StreamState.OPEN) {
          const pending = this.pendingStreams.get(streamId);
          if (pending) {
            clearTimeout(pending.timeout);
            this.pendingStreams.delete(streamId);
            pending.resolve(stream);
          }
        } else if (state === StreamState.ERROR || state === StreamState.CLOSED) {
          const pending = this.pendingStreams.get(streamId);
          if (pending) {
            clearTimeout(pending.timeout);
            this.pendingStreams.delete(streamId);
            pending.reject(new Error(`Stream failed to open: ${state}`));
          }
        }
      });
    });
  }

  /**
   * Accept incoming stream (called by transport implementation)
   * @param {string} streamId
   * @param {Object} metadata
   * @returns {Stream}
   */
  _acceptStream(streamId, metadata) {
    const stream = new Stream({
      streamId,
      transport: this,
      initiator: 'remote',
      metadata
    });

    this.streams.set(streamId, stream);
    stream._setState(StreamState.OPEN);
    this.emit('stream', stream);
    return stream;
  }

  _removeStream(streamId) {
    this.streams.delete(streamId);
  }

  getStream(streamId) {
    return this.streams.get(streamId);
  }

  // ─── Abstract Methods (to be implemented by specific transports) ──

  /**
   * Send stream open message
   * @protected
   */
  async _sendStreamOpen(streamId, type, metadata, capability) {
    throw new Error('_sendStreamOpen must be implemented by subclass');
  }

  /**
   * Send stream message
   * @protected
   */
  async _sendStreamMessage(message) {
    throw new Error('_sendStreamMessage must be implemented by subclass');
  }

  /**
   * Handle incoming stream message
   * @protected
   */
  _handleStreamMessage(message) {
    const stream = this.streams.get(message.streamId);
    if (stream) {
      stream._receive(message);
    } else if (message.type === 'headers' || message.type === 'data') {
      // Stream might not exist yet - could be race condition
      this.logger?.warn?.(`Received message for unknown stream: ${message.streamId}`);
    }
  }

  // ─── Request/Response Helpers ─────────────────────────────────────

  /**
   * Unary RPC call
   * @param {string} method
   * @param {*} payload
   * @param {Object} [options]
   * @returns {Promise<*>}
   */
  async call(method, payload, options = {}) {
    const stream = await this.openStream({
      type: StreamType.REQUEST_RESPONSE,
      metadata: { method, ...options.metadata }
    });

    await stream.write(payload, {}, true); // End stream after request

    // Wait for response
    for await (const data of stream) {
      if (data.headers && data.headers[':status']) {
        const status = data.headers[':status'];
        if (status >= 400) {
          throw new Error(`RPC error ${status}: ${data.payload}`);
        }
      }
      return data.payload;
    }

    throw new Error('No response received');
  }

  /**
   * Server streaming RPC
   * @param {string} method
   * @param {*} payload
   * @returns {AsyncIterable<*>}
   */
  async *serverStream(method, payload) {
    const stream = await this.openStream({
      type: StreamType.SERVER_STREAMING,
      metadata: { method }
    });

    await stream.write(payload, {}, true);

    for await (const data of stream) {
      yield data;
    }
  }

  /**
   * Client streaming RPC
   * @param {string} method
   * @returns {Object} { write, end, response }
   */
  async clientStream(method) {
    const stream = await this.openStream({
      type: StreamType.CLIENT_STREAMING,
      metadata: { method }
    });

    return {
      write: (data) => stream.write(data),
      end: () => stream.close(),
      response: new Promise((resolve, reject) => {
        stream.once('data', (data) => resolve(data));
        stream.once('error', reject);
        stream.once('close', () => reject(new Error('Stream closed without response')));
      })
    };
  }

  /**
   * Bidirectional streaming RPC
   * @param {string} method
   * @returns {Object} { write, read, close }
   */
  async bidiStream(method) {
    const stream = await this.openStream({
      type: StreamType.BIDI_STREAMING,
      metadata: { method }
    });

    return {
      write: (data) => stream.write(data),
      read: () => stream.read(),
      [Symbol.asyncIterator]: () => stream[Symbol.asyncIterator](),
      close: (error) => stream.close(error)
    };
  }
}

// ─── WebSocket Transport Implementation ────────────────────────────

export class WebSocketTransport extends Transport {
  constructor(ws, options = {}) {
    super(options);
    this.ws = ws;
    this.logger = options.logger || console;
    this.setupWebSocket();
  }

  setupWebSocket() {
    this.ws.on('message', (data) => this._handleMessage(data));
    this.ws.on('close', () => this._handleClose());
    this.ws.on('error', (err) => this._handleError(err));
  }

  async _sendStreamOpen(streamId, type, metadata, capability) {
    const message = {
      type: 'stream_open',
      streamId,
      streamType: type,
      metadata,
      capability: capability?.serialize(),
      timestamp: Date.now()
    };
    return this._send(message);
  }

  async _sendStreamMessage(message) {
    const envelope = {
      type: 'stream_message',
      streamId: message.streamId,
      message: message.serialize(),
      timestamp: Date.now()
    };
    return this._send(envelope);
  }

  _send(envelope) {
    return new Promise((resolve, reject) => {
      if (this.ws.readyState !== 1) {
        reject(new Error('WebSocket not connected'));
        return;
      }
      try {
        this.ws.send(JSON.stringify(envelope), (err) => {
          if (err) reject(err);
          else resolve(true);
        });
      } catch (e) {
        reject(e);
      }
    });
  }

  _handleMessage(data) {
    try {
      const envelope = JSON.parse(data.toString());
      
      switch (envelope.type) {
        case 'stream_open':
          this._handleStreamOpen(envelope);
          break;
        case 'stream_message':
          this._handleStreamMessage(StreamMessage.deserialize(envelope.message));
          break;
        case 'stream_ack':
          this._handleStreamAck(envelope);
          break;
        default:
          this.emit('message', envelope);
      }
    } catch (e) {
      this.logger.error('WS transport message error', e);
    }
  }

  _handleStreamOpen(envelope) {
    const { streamId, streamType, metadata, capability } = envelope;
    
    // Verify capability if provided
    if (capability && this.options.capabilityStore) {
      this.options.capabilityStore.authorize(capability, {
        resource: `stream:${streamType}`,
        action: 'open'
      }).then(auth => {
        if (!auth.valid) {
          this._sendStreamError(streamId, `Capability denied: ${auth.reason}`);
          return;
        }
        
        const stream = this._acceptStream(streamId, metadata);
        stream.metadata.capability = auth.capability;
      });
    } else {
      this._acceptStream(streamId, metadata);
    }
  }

  _handleStreamAck(envelope) {
    const { streamId, success, error } = envelope;
    const pending = this.pendingStreams.get(streamId);
    if (pending) {
      clearTimeout(pending.timeout);
      this.pendingStreams.delete(streamId);
      if (success) {
        const stream = this.streams.get(streamId);
        if (stream) stream._setState(StreamState.OPEN);
        pending.resolve(stream);
      } else {
        this.streams.delete(streamId);
        pending.reject(new Error(error || 'Stream rejected'));
      }
    }
  }

  async _sendStreamError(streamId, error) {
    await this._send({
      type: 'stream_ack',
      streamId,
      success: false,
      error,
      timestamp: Date.now()
    });
  }

  _handleClose() {
    this.emit('close');
    // Close all streams
    for (const stream of this.streams.values()) {
      stream._setState(StreamState.CLOSED);
      stream.emit('close', new Error('Transport closed'));
    }
    this.streams.clear();
  }

  _handleError(err) {
    this.emit('error', err);
  }
}

// ─── Transport Factory ──────────────────────────────────────────────

export function createTransport(type, connection, options = {}) {
  switch (type) {
    case 'websocket':
      return new WebSocketTransport(connection, options);
    // case 'grpc':
    //   return new GrpcTransport(connection, options);
    // case 'webtransport':
    //   return new WebTransportTransport(connection, options);
    default:
      throw new Error(`Unknown transport type: ${type}`);
  }
}

// ─── Stream Multiplexer (multiple logical streams over one transport) ──

export class StreamMultiplexer {
  constructor(transport) {
    this.transport = transport;
    this.channels = new Map(); // channelName -> Set<Stream>
  }

  /**
   * Subscribe to a pub/sub channel
   * @param {string} channel
   * @param {Capability} capability
   * @returns {AsyncIterable<*>}
   */
  async *subscribe(channel, capability) {
    const stream = await this.transport.openStream({
      type: StreamType.PUBSUB,
      metadata: { channel, subscribe: true },
      capability
    });

    // Register channel
    if (!this.channels.has(channel)) {
      this.channels.set(channel, new Set());
    }
    this.channels.get(channel).add(stream);

    try {
      for await (const data of stream) {
        yield data;
      }
    } finally {
      const channelStreams = this.channels.get(channel);
      if (channelStreams) {
        channelStreams.delete(stream);
        if (channelStreams.size === 0) {
          this.channels.delete(channel);
        }
      }
    }
  }

  /**
   * Publish to a channel
   * @param {string} channel
   * @param {*} data
   * @param {Capability} capability
   */
  async publish(channel, data, capability) {
    // Open temporary stream for publish
    const stream = await this.transport.openStream({
      type: StreamType.PUBSUB,
      metadata: { channel, publish: true },
      capability
    });

    await stream.write(data, {}, true);
    await stream.close();
  }
}

export default {
  Stream,
  StreamMessage,
  Transport,
  WebSocketTransport,
  StreamMultiplexer,
  StreamType,
  StreamState,
  createTransport
};