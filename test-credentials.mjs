// Does an unknown agent leak existence via response timing? bcrypt.compare
// against a dummy hash should make both paths cost roughly the same.
import { AgentCredentialStore } from './src/agent-credentials.js';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const dir = mkdtempSync(join(tmpdir(), 'credtest-'));
const store = new AgentCredentialStore({ dataDir: dir });

await store.register('hermes', 'a'.repeat(48));
await store.register('opencode', 'b'.repeat(48));

const time = async (fn) => {
  const t = process.hrtime.bigint();
  await fn();
  return Number(process.hrtime.bigint() - t) / 1e6;
};

// warm up
for (let i = 0; i < 3; i++) await store.verify('hermes', 'a'.repeat(48));

console.log("=== verify() timing, 5 samples each (ms) ===");
for (const [label, id, secret] of [
  ['known agent, CORRECT secret ', 'hermes', 'a'.repeat(48)],
  ['known agent, WRONG secret   ', 'hermes', 'z'.repeat(48)],
  ['UNKNOWN agent, any secret   ', 'nope-not-real', 'z'.repeat(48)],
]) {
  const times = [];
  for (let i = 0; i < 5; i++) times.push(await time(() => store.verify(id, secret)));
  const avg = times.reduce((a, b) => a + b) / times.length;
  console.log(`  ${label} avg=${avg.toFixed(1)}ms  [${times.map(t => t.toFixed(0)).join(', ')}]`);
}

console.log("\n=== secret strength gate ===");
// Note: these are plain literals, not regex. The module counts character
// classes, so 'a'*48 is correctly rejected (one class = low entropy even
// though it is 48 chars) while mixed-class strings pass.
const cases = [
  ['a'.repeat(48), false, '48 lowercase - one class'],
  ['A'.repeat(48), false, '48 uppercase - one class'],
  ['a'.repeat(16), false, '16 chars - too short'],
  ['password', false, 'dictionary word'],
  ['a'.repeat(2000), false, '2000 chars - absurd'],
  ['Xk9$mQ2!vLp4@Rn7#Tz5&Wy3*Hd8^uJq6%', true, 'mixed classes, 32+ chars'],
  ['Xk9$mQ2!', false, 'mixed but only 8 chars - too short'],
  ['a'.repeat(30) + '!!!!!!!!!!', true, 'long + symbols'],
  ['a'.repeat(30) + 'ABCDEFGH', true, 'lowercase + uppercase'],
];
let ok = true;
for (const [s, want, label] of cases) {
  const got = AgentCredentialStore.isPlausibleSecret(s);
  const mark = got === want ? 'PASS' : 'FAIL';
  if (got !== want) ok = false;
  console.log(`  [${mark}] ${label} -> ${got}`);
}

console.log("\n=== generated secret entropy ===");
const sec = AgentCredentialStore.generateSecret();
const uniq = new Set(sec).size;
console.log(`  length=${sec.length} distinct_chars=${uniq}`);
console.log(`  [${uniq >= 20 ? 'PASS' : 'FAIL'}] diversity`);

console.log("\n=== registry is not world-readable ===");
import { statSync } from 'fs';
const mode = (statSync(store.path).mode & 0o777).toString(8);
console.log(`  mode=${mode}  [${mode === '600' ? 'PASS' : 'FAIL'}]`);

rmSync(dir, { recursive: true, force: true });
process.exit(ok && uniq >= 20 && mode === '600' ? 0 : 1);
