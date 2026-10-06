/**
 * test-ws-session.mjs — end-to-end WebSocket check with TWO real agents.
 *
 * Sessions are created over the WebSocket (there is no REST POST), so this is
 * the only way to prove hermes and opencode can actually coordinate. Secrets
 * are read from the 0600 config and never printed.
 */
import { readFileSync } from 'fs';
import WebSocket from 'ws';

const CONF = '/home/livings/.config/coordination-server/agents';
const URL = 'ws://127.0.0.1:4126/ws';

const creds = (a) => {
  const t = readFileSync(`${CONF}/${a}.env`, 'utf8');
  const g = (k) => (t.split('\n').find((l) => l.startsWith(k + '=')) || '').split('=').slice(1).join('=');
  return { id: g('COORD_AGENT_ID'), secret: g('COORD_AGENT_SECRET') };
};

const token = async (a) => {
  const c = creds(a);
  const r = await fetch('http://127.0.0.1:4126/api/auth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agentId: c.id, secret: c.secret }),
  });
  return (await r.json()).token;
};

const open = (tok, agentId) =>
  new Promise((resolve, reject) => {
    const ws = new WebSocket(URL);
    const frames = [];
    const timer = setTimeout(() => reject(new Error('timeout')), 15000);
    ws.on('open', () => ws.send(JSON.stringify({ type: 'auth', token: tok })));
    ws.on('message', (d) => {
      const m = JSON.parse(d.toString());
      frames.push(m);
      if (m.type === 'welcome') ws.send(JSON.stringify({ type: 'auth', token: tok }));
      if (m.type === 'auth_result' && m.success === false) {
        clearTimeout(timer); ws.close(); return reject(new Error('auth failed: ' + m.reason));
      }
      // An unregistered-in-memory agent is told to send registration info.
      // The server confirms with {type:'auth_result', success:true, registered:true}
      // — note it is still an auth_result frame, not a 'registered' frame.
      if (m.type === 'auth_result' && m.registered === false) {
        ws.send(JSON.stringify({
          type: 'register', agentId,
          info: { name: agentId, type: 'agent', version: '1.0.0' },
        }));
      }
      if (m.type === 'auth_result' && m.registered === true) {
        clearTimeout(timer); resolve({ ws, frames });
      }
    });
    ws.on('error', reject);
  });

let pass = 0, fail = 0;
const chk = (label, cond) => {
  console.log(`[${cond ? 'PASS' : 'FAIL'}] ${label}`);
  cond ? pass++ : fail++;
};

try {
  const th = await token('hermes');
  const to = await token('opencode');
  chk('hermes obtained a token', Boolean(th));
  chk('opencode obtained a token', Boolean(to));

  const h = await open(th, 'hermes');
  chk('hermes WebSocket authenticated', h.frames.some((f) => f.type === 'auth_result' && f.registered === true));

  const o = await open(to, 'opencode');
  chk('opencode WebSocket authenticated', o.frames.some((f) => f.type === 'auth_result' && f.registered === true));

  // Both are connected at once -> the hub sees two live agents.
  await new Promise((r) => setTimeout(r, 700));
  const health = await (await fetch('http://127.0.0.1:4126/health')).json();
  chk(`hub reports 2 connected agents (got ${health.agents})`, health.agents === 2);

  // hermes creates a session over the socket.
  // Frame shape notes, all learned from the source:
  //   - the dispatcher reads message.payload, so fields go inside `payload`
  //   - createSession() assigns its own uuidv4 and ignores any client id
  //   - the reply frame is {type:'session_created', session:{...}}
  h.ws.send(JSON.stringify({
    type: 'session_create',
    payload: {
      name: 'hermes-opencode',
      visibility: 'private',
      description: 'e2e coordination check',
    },
  }));
  await new Promise((r) => setTimeout(r, 1200));

  const created = h.frames.find((f) => f.type === 'session_created');
  if (!created) {
    console.log('       frames seen:', h.frames.map((f) => f.type).join(', '));
    chk('hermes received a session_created frame', false);
  } else {
    const sid = created.session?.id;
    chk(`hermes received a server-assigned session id (${String(sid).slice(0, 8)}…)`, Boolean(sid));

    const rest = await (await fetch(
      'http://127.0.0.1:4126/api/sessions', { headers: { Authorization: `Bearer ${to}` } }
    )).json();
    chk('opencode can read hermes\'s session over REST', JSON.stringify(rest).includes(sid));
  }

  h.ws.close(); o.ws.close();
  await new Promise((r) => setTimeout(r, 300));
} catch (e) {
  console.log('[FAIL] exception:', e.message);
  fail++;
}

console.log(`\nws PASS=${pass} FAIL=${fail}`);
process.exit(fail === 0 ? 0 : 1);
