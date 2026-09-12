import { spawn } from 'child_process';
import http from 'http';
import WebSocket from 'ws';

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

setTimeout(() => {
  console.log('Connecting to WebSocket...');
  const ws = new WebSocket('ws://localhost:4126/ws');
  
  ws.on('open', () => {
    console.log('Connected, getting token...');
    const req = http.request({
      hostname: 'localhost',
      port: 4126,
      path: '/api/auth/token',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      timeout: 3000
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const { token } = JSON.parse(data);
          console.log('Got token:', token.substring(0, 20) + '...');
          console.log('Sending auth...');
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
    req.on('timeout', () => {
      console.error('Token request timeout');
      req.destroy();
      server.kill();
      process.exit(1);
    });
    req.write(JSON.stringify({ agentId: 'test-client', secret: 'test-secret' }));
    req.end();
  });
  
  ws.on('message', (data) => {
    console.log('Received from server:', data.toString());
    ws.close();
    server.kill();
    process.exit(0);
  });
  
  ws.on('error', (e) => {
    console.error('WS Error:', e.message);
    server.kill();
    process.exit(1);
  });
  
  ws.on('close', () => {
    console.log('WS closed');
    server.kill();
    process.exit(0);
  });
  
  setTimeout(() => {
    console.log('Timeout');
    server.kill();
    process.exit(1);
  }, 10000);
}, 3000);

server.on('close', (code) => {
  console.log(`Server exited with code ${code}`);
});