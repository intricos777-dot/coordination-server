#!/usr/bin/env node
// Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work

// Start coordination server in child process
const { spawn } = require('child_process');

const server = spawn('node', ['src/index.js'], {
  cwd: '/home/sin/coordination-server',
  env: { 
    ...process.env, 
    COORD_JWT_SECRET: 'test-secret',
    COORD_ADMIN_TOKEN: 'admin'
  },
  stdio: ['ignore', 'pipe', 'pipe']
});

server.stdout.on('data', (data) => {
  console.log('[SERVER]', data.toString().trim());
});

server.stderr.on('data', (data) => {
  console.error('[SERVER ERR]', data.toString().trim());
});

// Wait for server to start
setTimeout(() => {
  console.log('Connecting to WebSocket...');
  const WebSocket = require('ws');
  const ws = new WebSocket('ws://localhost:4126/ws');
  
  ws.on('open', () => {
    console.log('Connected, sending auth...');
    // First get a valid token
    const http = require('http');
    const req = http.request({
      hostname: 'localhost',
      port: 4126,
      path: '/api/auth/token',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const { token } = JSON.parse(data);
          console.log('Got token, sending auth...');
          ws.send(JSON.stringify({ type: 'auth', token }));
        } catch (e) {
          console.error('Token parse error:', e);
          ws.close();
          server.kill();
          process.exit(1);
        }
      });
    });
    req.on('error', (e) => {
      console.error('Token request error:', e);
      server.kill();
      process.exit(1);
    });
    req.write(JSON.stringify({ agentId: 'test-client', secret: 'test-secret' }));
    req.end();
  });
  
  ws.on('message', (data) => {
    console.log('Received:', data.toString());
    ws.close();
    server.kill();
    process.exit(0);
  });
  
  ws.on('error', (e) => {
    console.error('WS Error:', e.message);
    server.kill();
    process.exit(1);
  });
  
  setTimeout(() => {
    console.log('Timeout');
    server.kill();
    process.exit(1);
  }, 5000);
}, 2000);

server.on('close', (code) => {
  console.log(`Server exited with code ${code}`);
});