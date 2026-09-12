import { spawn } from 'child_process';
import { execSync } from 'child_process';
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
    console.log('Connected, getting token with curl...');
    try {
      const result = execSync('curl -s -X POST http://localhost:4126/api/auth/token -H "Content-Type: application/json" -d \'{"agentId":"test-client","secret":"test-secret"}\'', { 
        timeout: 5000,
        encoding: 'utf8'
      });
      const { token } = JSON.parse(result.trim());
      console.log('Got token:', token.substring(0, 20) + '...');
      console.log('Sending auth...');
      ws.send(JSON.stringify({ type: 'auth', token }));
    } catch (e) {
      console.error('Token request error:', e.message);
      ws.close();
      server.kill();
      process.exit(1);
    }
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