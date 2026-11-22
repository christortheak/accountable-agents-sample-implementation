// Start the trust anchor, then every directory and records service, each as its
// own process; wait until they answer; then have the directories accredit the
// records services (OpenID Federation Trust Marks).
import { spawn } from 'node:child_process';
import path from 'node:path';
import { setupFederation, accreditAll, federationIsRunning } from '../src/lib/federation.js';
import { PROJECT_ROOT, discoverFederation } from '../src/lib/trust.js';

const setup = setupFederation();
const { trustAnchor, paths, config } = setup;
if (await federationIsRunning(setup)) {
  console.log('Federation is already running.');
  process.exit(0);
}

const children = [];
const launch = (script, args = []) => {
  const child = spawn(process.execPath, [path.join(PROJECT_ROOT, script), ...args], { cwd: PROJECT_ROOT, stdio: ['ignore', 'inherit', 'inherit'] });
  child.on('exit', (code) => {
    if (code) console.error(`[${args[0] ?? script}] exited with code ${code}`);
  });
  children.push(child);
};
const stop = () => {
  for (const c of children) c.kill('SIGTERM');
  process.exit(0);
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);

launch('src/trustanchor/server.js');
for (const svc of config.services) launch(svc.kind === 'directory' ? 'src/directory/server.js' : 'src/records/server.js', [svc.id]);

const deadline = Date.now() + Number(process.env.AAF_STARTUP_TIMEOUT_SECONDS ?? 15) * 1000;
while (!(await federationIsRunning(setup))) {
  if (Date.now() > deadline) {
    console.error('Services did not start in time.');
    stop();
  }
  await new Promise((r) => setTimeout(r, 150));
}
const trustList = await discoverFederation(trustAnchor);
for (const a of await accreditAll({ trustList, paths, config })) console.log(`  ${a.directory} ${a.already ? 'already accredits' : 'accredits'} ${a.rs} (${a.types.length} trust mark(s))`);
console.log('\nFederation running. Dashboards:');
console.log(`  ${trustAnchor.name.padEnd(50)} ${trustAnchor.url}/`);
for (const s of [...trustList.directories, ...trustList.recordsServices]) console.log(`  ${s.name.padEnd(50)} ${s.url}/`);
console.log('\nRun the simulator in another terminal:  npm run sim');
console.log('Press Ctrl+C to stop.');
