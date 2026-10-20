# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
"""
Coordination Server Python Client SDK

Usage:
    from coordination_client import CoordinationClient
    
    async def main():
        client = CoordinationClient(server_url="ws://localhost:4126/ws")
        await client.connect(agent_id="my-agent", name="My Agent", type="python")
        
        # Send messages
        await client.send_direct_message("other-agent", {"hello": "world"})
        
        # Create/join sessions
        session = await client.create_session(name="my-session")
        await client.join_session(session.id)
        await client.send_session_message(session.id, {"text": "Hello session!"})
        
        # Streaming
        async for msg in client.server_stream("chat", {"user": "me"}):
            print(msg)
        
        await client.disconnect()

    asyncio.run(main())
"""

import asyncio
import json
import uuid
import logging
from typing import Dict, List, Optional, Any, AsyncIterator, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
import websockets
from websockets.client import WebSocketClientProtocol
import aiohttp

logger = logging.getLogger(__name__)


# ─── Types ────────────────────────────────────────────────────────────

class StreamType(str, Enum):
    REQUEST_RESPONSE = "request_response"
    SERVER_STREAMING = "server_streaming"
    CLIENT_STREAMING = "client_streaming"
    BIDI_STREAMING = "bidi_streaming"
    PUBSUB = "pubsub"
    EVENT_SOURCE = "event_source"


@dataclass
class AgentInfo:
    id: str
    name: str
    type: str
    version: str
    capabilities: List[str]
    metadata: Dict[str, Any]
    status: str
    connected_at: int
    last_heartbeat: int
    subscriptions: List[str]


@dataclass
class Session:
    id: str
    owner: str
    name: str
    description: str
    tags: List[str]
    visibility: str
    participants: List[str]
    message_count: int
    created_at: int
    updated_at: int
    metadata: Dict[str, Any]


@dataclass
class StreamMessage:
    stream_id: str
    type: str  # 'data', 'headers', 'close', 'error'
    payload: Any
    headers: Dict[str, str] = field(default_factory=dict)
    flags: int = 0
    timestamp: int = 0
    sequence: int = 0


class Stream:
    """Async stream for bidirectional communication"""
    
    def __init__(self, stream_id: str, stream_type: StreamType, metadata: Dict, client: 'CoordinationClient'):
        self.stream_id = stream_id
        self.stream_type = stream_type
        self.metadata = metadata
        self.client = client
        self.closed = False
        self._buffer: asyncio.Queue = asyncio.Queue()
        self._pending_read: Optional[asyncio.Future] = None
    
    def write(self, data: Any, end_stream: bool = False):
        """Write data to stream"""
        if self.closed:
            raise RuntimeError("Stream is closed")
        
        message = {
            "type": "stream_message",
            "stream_id": self.stream_id,
            "message": json.dumps({
                "stream_id": self.stream_id,
                "type": "data",
                "payload": data,
                "flags": 1 if end_stream else 0
            })
        }
        self.client._send(message)
        
        if end_stream:
            self.close()
    
    def close(self, error: Optional[Exception] = None):
        """Close the stream"""
        if self.closed:
            return
        
        self.closed = True
        
        message = {
            "type": "stream_message",
            "stream_id": self.stream_id,
            "message": json.dumps({
                "stream_id": self.stream_id,
                "type": "error" if error else "close",
                "payload": str(error) if error else None
            })
        }
        self.client._send(message)
        
        # Unblock any pending read
        if self._pending_read and not self._pending_read.done():
            self._pending_read.set_result(None)
    
    def __aiter__(self):
        return self
    
    async def __anext__(self) -> Any:
        if self.closed and self._buffer.empty():
            raise StopAsyncIteration
        
        try:
            item = await asyncio.wait_for(self._buffer.get(), timeout=30.0)
            if item is None:  # Close signal
                raise StopAsyncIteration
            return item
        except asyncio.TimeoutError:
            raise StopAsyncIteration
    
    async def read(self) -> Optional[Any]:
        """Read next message from stream"""
        if self.closed and self._buffer.empty():
            return None
        
        try:
            return await asyncio.wait_for(self._buffer.get(), timeout=30.0)
        except asyncio.TimeoutError:
            return None
    
    def _receive(self, payload: Any):
        """Internal: receive data from client"""
        self._buffer.put_nowait(payload)
        if self._pending_read and not self._pending_read.done():
            self._pending_read.set_result(payload)
            self._pending_read = None


# ─── Main Client ──────────────────────────────────────────────────────

class CoordinationClient:
    """
    Async client for the Coordination Server.
    
    Supports:
    - JWT and Capability-based authentication
    - Direct messaging, broadcasting, sessions
    - Streaming (bidi, server, client)
    - Federation (multi-node)
    - Capability delegation
    """
    
    def __init__(
        self,
        server_url: str = "ws://localhost:4126/ws",
        rest_url: Optional[str] = None,
        agent_id: Optional[str] = None,
        name: Optional[str] = None,
        type: str = "python",
        version: str = "1.0.0",
        capabilities: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        max_reconnect_attempts: int = 10,
        reconnect_delay: float = 2.0,
        request_timeout: float = 10.0
    ):
        self.server_url = server_url
        self.rest_url = rest_url or server_url.replace("ws://", "http://").replace("wss://", "https://").replace("/ws", "")
        self.agent_id = agent_id
        self.name = name or agent_id or f"agent-{uuid.uuid4().hex[:8]}"
        self.type = type
        self.version = version
        self.capabilities = capabilities or []
        self.metadata = metadata or {}
        
        self.max_reconnect_attempts = max_reconnect_attempts
        self.reconnect_delay = reconnect_delay
        self.request_timeout = request_timeout
        
        self.ws: Optional[WebSocketClientProtocol] = None
        self.token: Optional[str] = None
        self.capability_token: Optional[str] = None
        self.connected = False
        self.authenticated = False
        
        self._message_id = 0
        self._pending_requests: Dict[int, asyncio.Future] = {}
        self._event_handlers: Dict[str, List[Callable]] = {}
        self._reconnect_attempts = 0
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._receive_task: Optional[asyncio.Task] = None
        self._streams: Dict[str, Stream] = {}
        
        # Session for HTTP requests
        self._http_session: Optional[aiohttp.ClientSession] = None
    
    # ─── Connection ───────────────────────────────────────────────────
    
    async def connect(self, *, agent_id: Optional[str] = None, token: Optional[str] = None, secret: Optional[str] = None) -> 'CoordinationClient':
        """Connect using JWT token or secret"""
        if agent_id:
            self.agent_id = agent_id
        if not self.agent_id:
            raise ValueError("agent_id required")
        
        if token:
            self.token = token
        elif secret:
            self.token = await self._get_token(self.agent_id, secret)
        else:
            raise ValueError("token or secret required")
        
        return await self._connect_websocket(auth_type="token")
    
    async def connect_with_capability(self, capability_token: str) -> 'CoordinationClient':
        """Connect using OCAP capability token"""
        self.capability_token = capability_token
        # Parse agent ID from capability (basic parsing)
        try:
            import base64
            payload = json.loads(base64.urlsafe_b64decode(capability_token + '==').decode())
            self.agent_id = payload.get('id')
        except Exception:
            pass
        
        if not self.agent_id:
            raise ValueError("Could not extract agent_id from capability")
        
        return await self._connect_websocket(auth_type="capability")
    
    async def _connect_websocket(self, auth_type: str) -> 'CoordinationClient':
        self.ws = await websockets.connect(self.server_url)
        self.connected = True
        self._reconnect_attempts = 0
        
        # Start receive loop
        self._receive_task = asyncio.create_task(self._receive_loop())
        
        # Send auth
        if auth_type == "token":
            await self._send({"type": "auth", "token": self.token})
        else:
            await self._send({"type": "auth_capability", "capability": self.capability_token, "agent_id": self.agent_id})
        
        # Wait for auth result
        try:
            result = await asyncio.wait_for(self._wait_for_event("auth_result"), timeout=self.request_timeout)
            if not result.get("success"):
                raise ConnectionError(result.get("reason", "Authentication failed"))
            
            self.authenticated = True
            
            if not result.get("registered"):
                await self._send({
                    "type": "register",
                    "agent_id": self.agent_id,
                    "info": {
                        "name": self.name,
                        "type": self.type,
                        "version": self.version,
                        "capabilities": self.capabilities,
                        "metadata": self.metadata
                    }
                })
                # Wait for registration result
                await asyncio.wait_for(self._wait_for_event("auth_result"), timeout=self.request_timeout)
            
            self._start_heartbeat()
            self.emit("connect")
            return self
            
        except asyncio.TimeoutError:
            await self.disconnect()
            raise ConnectionError("Connection timeout")
    
    async def _get_token(self, agent_id: str, secret: str) -> str:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.rest_url}/api/auth/token",
                json={"agent_id": agent_id, "secret": secret}
            ) as resp:
                if resp.status != 200:
                    raise ConnectionError("Failed to get token")
                data = await resp.json()
                return data["token"]
    
    def _start_heartbeat(self):
        async def heartbeat():
            while self.connected and self.ws:
                try:
                    await self._send({"type": "heartbeat"})
                    await asyncio.sleep(30)
                except Exception:
                    break
        
        self._heartbeat_task = asyncio.create_task(heartbeat())
    
    # ─── Capability Management ────────────────────────────────────────
    
    async def request_capability(self, identifier: str, caveats: Optional[List[Dict]] = None, ttl: Optional[int] = None, metadata: Optional[Dict] = None) -> str:
        """Request a new capability from the server"""
        if not self.token:
            raise RuntimeError("Not authenticated with token")
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.rest_url}/api/capabilities/issue",
                headers={"Authorization": f"Bearer {self.token}"},
                json={"identifier": identifier, "caveats": caveats or [], "ttl": ttl, "metadata": metadata or {}}
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError("Failed to request capability")
                data = await resp.json()
                return data["capability"]
    
    async def delegate_capability(self, parent_capability: str, identifier: str, caveats: Optional[List[Dict]] = None, ttl: Optional[int] = None) -> str:
        """Delegate a capability"""
        if not self.token:
            raise RuntimeError("Not authenticated with token")
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.rest_url}/api/capabilities/delegate",
                headers={"Authorization": f"Bearer {self.token}"},
                json={"parent_capability": parent_capability, "identifier": identifier, "caveats": caveats or [], "ttl": ttl}
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError("Failed to delegate capability")
                data = await resp.json()
                return data["capability"]
    
    # ─── Session Management ───────────────────────────────────────────
    
    async def create_session(self, **options) -> Session:
        result = await self._request("session_create", options)
        return Session(**result["session"])
    
    async def join_session(self, session_id: str) -> bool:
        result = await self._request("session_join", {"session_id": session_id})
        return result.get("success", False)
    
    async def leave_session(self, session_id: str) -> bool:
        result = await self._request("session_leave", {"session_id": session_id})
        return result.get("success", False)
    
    async def send_session_message(self, session_id: str, content: Any) -> bool:
        result = await self._request("session_message", {"session_id": session_id, "content": content})
        return result.get("success", False)
    
    async def get_session_messages(self, session_id: str, limit: int = 100, offset: int = 0) -> Dict:
        if not self.token:
            raise RuntimeError("Not authenticated")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.rest_url}/api/sessions/{session_id}/messages",
                params={"limit": limit, "offset": offset},
                headers={"Authorization": f"Bearer {self.token}"}
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError("Failed to fetch messages")
                return await resp.json()
    
    async def list_sessions(self, visibility: Optional[str] = None, participant: Optional[str] = None) -> List[Session]:
        if not self.token:
            raise RuntimeError("Not authenticated")
        
        params = {}
        if visibility:
            params["visibility"] = visibility
        if participant:
            params["participant"] = participant
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.rest_url}/api/sessions",
                params=params,
                headers={"Authorization": f"Bearer {self.token}"}
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError("Failed to list sessions")
                data = await resp.json()
                return [Session(**s) for s in data["sessions"]]
    
    # ─── Direct Messaging ─────────────────────────────────────────────
    
    async def send_direct_message(self, target_agent_id: str, payload: Any) -> bool:
        result = await self._request("direct", {"target": target_agent_id, "payload": payload})
        return result.get("success", False)
    
    async def broadcast(self, payload: Any) -> Dict:
        return await self._request("broadcast", {"payload": payload})
    
    # ─── Subscriptions ────────────────────────────────────────────────
    
    async def subscribe(self, channel: str) -> bool:
        result = await self._request("subscribe", {"channel": channel})
        return result.get("success", False)
    
    async def unsubscribe(self, channel: str) -> bool:
        result = await self._request("unsubscribe", {"channel": channel})
        return result.get("success", False)
    
    # ─── Streaming ────────────────────────────────────────────────────
    
    async def open_stream(self, stream_type: StreamType = StreamType.BIDI_STREAMING, metadata: Optional[Dict] = None) -> Stream:
        """Open a bidirectional stream"""
        stream_id = f"stream-{uuid.uuid4().hex[:8]}"
        stream = Stream(stream_id, stream_type, metadata or {}, self)
        self._streams[stream_id] = stream
        
        # Send stream open
        await self._send({
            "type": "stream_open",
            "stream_id": stream_id,
            "stream_type": stream_type.value,
            "metadata": metadata or {},
            "capability": self.capability_token
        })
        
        # Wait for ack
        ack_event = f"stream_ack_{stream_id}"
        try:
            ack = await asyncio.wait_for(self._wait_for_event(ack_event), timeout=10.0)
            if not ack.get("success"):
                del self._streams[stream_id]
                raise RuntimeError(ack.get("error", "Stream open failed"))
        except asyncio.TimeoutError:
            del self._streams[stream_id]
            raise RuntimeError("Stream open timeout")
        
        return stream
    
    async def server_stream(self, method: str, payload: Any) -> AsyncIterator[Any]:
        """Open a server-streaming RPC"""
        stream = await self.open_stream(StreamType.SERVER_STREAMING, {"method": method})
        await stream.write(payload, end_stream=True)
        async for item in stream:
            yield item
    
    async def bidi_stream(self, method: str) -> Stream:
        """Open a bidirectional streaming RPC"""
        return await self.open_stream(StreamType.BIDI_STREAMING, {"method": method})
    
    # ─── Federation ───────────────────────────────────────────────────
    
    async def locate_agent(self, agent_id: str) -> Dict:
        if not self.token:
            raise RuntimeError("Not authenticated")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.rest_url}/api/federation/agents/{agent_id}",
                headers={"Authorization": f"Bearer {self.token}"}
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError("Failed to locate agent")
                return await resp.json()
    
    async def list_peers(self) -> List[Dict]:
        if not self.token:
            raise RuntimeError("Not authenticated")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.rest_url}/api/federation/peers",
                headers={"Authorization": f"Bearer {self.token}"}
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError("Failed to list peers")
                data = await resp.json()
                return data["peers"]
    
    async def list_federated_sessions(self) -> List[Dict]:
        if not self.token:
            raise RuntimeError("Not authenticated")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.rest_url}/api/federation/sessions",
                headers={"Authorization": f"Bearer {self.token}"}
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError("Failed to list federated sessions")
                data = await resp.json()
                return data["sessions"]
    
    # ─── Agent Registry ───────────────────────────────────────────────
    
    async def list_agents(self) -> List[AgentInfo]:
        if not self.token:
            raise RuntimeError("Not authenticated")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.rest_url}/api/agents",
                headers={"Authorization": f"Bearer {self.token}"}
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError("Failed to list agents")
                data = await resp.json()
                return [AgentInfo(**a) for a in data["agents"]]
    
    async def get_agent(self, agent_id: str) -> AgentInfo:
        if not self.token:
            raise RuntimeError("Not authenticated")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.rest_url}/api/agents/{agent_id}",
                headers={"Authorization": f"Bearer {self.token}"}
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError("Failed to get agent")
                data = await resp.json()
                return AgentInfo(**data)
    
    # ─── Internal ─────────────────────────────────────────────────────
    
    def _send(self, message: Dict):
        """Send message over WebSocket"""
        if self.ws and not self.ws.closed:
            self.ws.send(json.dumps(message))
    
    async def _request(self, msg_type: str, payload: Dict) -> Dict:
        """Send request and wait for response"""
        if not self.connected or not self.authenticated:
            raise RuntimeError("Not connected or authenticated")
        
        self._message_id += 1
        msg_id = self._message_id
        
        future = asyncio.get_event_loop().create_future()
        self._pending_requests[msg_id] = future
        
        await self._send({"type": msg_type, "payload": payload, "id": msg_id})
        
        try:
            return await asyncio.wait_for(future, timeout=self.request_timeout)
        except asyncio.TimeoutError:
            self._pending_requests.pop(msg_id, None)
            raise TimeoutError("Request timeout")
    
    async def _receive_loop(self):
        """Main receive loop"""
        try:
            async for message in self.ws:
                await self._handle_message(json.loads(message))
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            logger.error(f"Receive loop error: {e}")
            self.emit("error", e)
        finally:
            await self._handle_disconnect()
    
    async def _handle_message(self, message: Dict):
        # Handle request responses
        if "id" in message and message["id"] in self._pending_requests:
            future = self._pending_requests.pop(message["id"])
            if not future.done():
                if message.get("success"):
                    future.set_result(message)
                else:
                    future.set_exception(RuntimeError(message.get("reason", "Request failed")))
            return
        
        # Handle stream ack
        if message.get("type") == "stream_ack" and "stream_id" in message:
            self.emit(f"stream_ack_{message['stream_id']}", message)
            return
        
        # Handle stream messages
        if message.get("type") == "stream_message" and "stream_id" in message:
            stream = self._streams.get(message["stream_id"])
            if stream and "message" in message:
                stream_msg = json.loads(message["message"])
                if stream_msg["type"] == "data":
                    stream._receive(stream_msg["payload"])
                elif stream_msg["type"] in ("close", "error"):
                    stream.closed = True
                    if stream._pending_read and not stream._pending_read.done():
                        stream._pending_read.set_result(None)
                    if stream_msg["type"] == "error":
                        self.emit("error", Exception(stream_msg.get("payload", "Stream error")))
            return
        
        # Emit event
        self.emit(message.get("type", "unknown"), message)
    
    def _wait_for_event(self, event: str) -> asyncio.Future:
        future = asyncio.get_event_loop().create_future()
        
        def handler(data):
            if not future.done():
                future.set_result(data)
        
        self.on(event, handler)
        
        # Cleanup handler after event
        def cleanup(data):
            self.off(event, handler)
        
        future.add_done_callback(lambda _: cleanup(None))
        
        return future
    
    async def _handle_disconnect(self):
        self.connected = False
        self.authenticated = False
        
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        if self._receive_task:
            self._receive_task.cancel()
        
        # Close all streams
        for stream in self._streams.values():
            stream.closed = True
        self._streams.clear()
        
        self.emit("disconnect")
        
        # Reconnect logic
        if self._reconnect_attempts < self.max_reconnect_attempts:
            self._reconnect_attempts += 1
            delay = self.reconnect_delay * (1.5 ** (self._reconnect_attempts - 1))
            logger.info(f"Reconnecting in {delay}s (attempt {self._reconnect_attempts})")
            await asyncio.sleep(delay)
            try:
                if self.token:
                    await self.connect(token=self.token)
                elif self.capability_token:
                    await self.connect_with_capability(self.capability_token)
            except Exception as e:
                logger.error(f"Reconnect failed: {e}")
    
    async def disconnect(self):
        """Gracefully disconnect"""
        self.connected = False
        
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        if self._receive_task:
            self._receive_task.cancel()
        
        for stream in self._streams.values():
            stream.close()
        self._streams.clear()
        
        if self.ws:
            await self.ws.close()
            self.ws = None
        
        self.authenticated = False
    
    # ─── Event System ─────────────────────────────────────────────────
    
    def on(self, event: str, handler: Callable):
        if event not in self._event_handlers:
            self._event_handlers[event] = []
        self._event_handlers[event].append(handler)
    
    def once(self, event: str, handler: Callable):
        def once_handler(*args, **kwargs):
            handler(*args, **kwargs)
            self.off(event, once_handler)
        self.on(event, once_handler)
    
    def off(self, event: str, handler: Callable):
        if event in self._event_handlers:
            try:
                self._event_handlers[event].remove(handler)
            except ValueError:
                pass
    
    def emit(self, event: str, *args, **kwargs):
        if event in self._event_handlers:
            for handler in self._event_handlers[event][:]:
                try:
                    handler(*args, **kwargs)
                except Exception as e:
                    logger.error(f"Event handler error: {e}")
    
    # ─── Context Manager ──────────────────────────────────────────────
    
    async def __aenter__(self) -> 'CoordinationClient':
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()


# ─── Factory ──────────────────────────────────────────────────────────

async def create_client(**options) -> CoordinationClient:
    """Create and connect a client"""
    client = CoordinationClient(**options)
    
    if "token" in options or "secret" in options:
        await client.connect(**{k: v for k, v in options.items() if k in ("token", "secret", "agent_id")})
    elif "capability" in options:
        await client.connect_with_capability(options["capability"])
    
    return client


# ─── Convenience Exports ──────────────────────────────────────────────

__all__ = [
    "CoordinationClient",
    "create_client",
    "AgentInfo",
    "Session",
    "Stream",
    "StreamType",
    "StreamMessage",
]


if __name__ == "__main__":
    # Example usage
    async def example():
        async with CoordinationClient() as client:
            await client.connect(agent_id="example-agent", secret="secret123")
            
            # Event handlers
            client.on("direct", lambda msg: print(f"Direct: {msg}"))
            client.on("broadcast", lambda msg: print(f"Broadcast: {msg}"))
            client.on("session_message", lambda msg: print(f"Session: {msg}"))
            
            # Create session
            session = await client.create_session(name="test-session")
            print(f"Created session: {session.id}")
            
            # Send message
            await client.send_session_message(session.id, {"text": "Hello!"})
            
            # Keep alive
            await asyncio.sleep(10)
    
    asyncio.run(example())