// Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
import { WebSocketServer } from 'ws';
import jwt from 'jsonwebtoken';

const JWT_SECRET = 'test-secret';
const PORT = 4127;

const wss = new WebSocketServer({ port: PORT });

console.log(`Test server running on ws://localhost:${PORT}`);

wss.on('connection', (ws, req) => {
  const clientIp = req.socket.remoteAddress;
  console.log(`[${new Date().toISOString()}] WS connection from ${clientIp}`);
  
  ws.send(JSON.stringify({ 
    type: 'welcome', 
    message: 'Test server - send auth',
    version: '1.0.0'
  }));
  
  ws.on('message', async (data) => {
    const raw = data.toString();
    console.log(`[${new Date().toISOString()}] Received raw: ${raw.substring(0, 200)}`);
    
    try {
      const message = JSON.parse(raw);
      console.log(`[${new Date().toISOString()}] Parsed message.type: ${message.type}, hasToken: ${!!message.token}`);
      
      if (message.type === 'auth' && message.token) {
        try {
          const decoded = jwt.verify(message.token, JWT_SECRET);
          console.log(`[${new Date().toISOString()}] JWT verified, agentId: ${decoded.sub}`);
          ws.send(JSON.stringify({ 
            type: 'auth_result', 
            success: true, 
            registered: false, 
            agentId: decoded.sub,
            message: 'Send registration info' 
          }));
        } catch (e) {
          console.log(`[${new Date().toISOString()}] JWT verify failed: ${e.message}`);
          ws.send(JSON.stringify({ type: 'auth_result', success: false, reason: 'Invalid token' }));
        }
        return;
      }
      
      // Not auth message
      console.log(`[${new Date().toISOString()}] Not auth message, sending NOT_AUTHENTICATED`);
      ws.send(JSON.stringify({ type: 'error', code: 'NOT_AUTHENTICATED' }));
      
    } catch (e) {
      console.error(`[${new Date().toISOString()}] Parse error: ${e.message}`);
      ws.send(JSON.stringify({ type: 'error', code: 'INVALID_MESSAGE' }));
    }
  });
  
  ws.on('close', () => {
    console.log(`[${new Date().toISOString()}] WS closed`);
  });
  
  ws.on('error', (err) => {
    console.error(`[${new Date().toISOString()}] WS error: ${err.message}`);
  });
});

console.log('Test server ready. Connect with a client to test.');