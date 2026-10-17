// Generate keys for every member in config/federation.json and write the trust
// anchor's records. Safe to re-run; --reset wipes all state first.
import { setupFederation } from '../src/lib/federation.js';

const reset = process.argv.includes('--reset');
const { trustAnchor, paths, config } = setupFederation({ reset });
console.log(`${reset ? 'Reset and re-created' : 'Prepared'} "${config.name}" in ${paths.dataDir}`);
console.log(`  trust anchor   ${trustAnchor.entity_id.padEnd(30)} ${trustAnchor.url}`);
for (const s of config.services) console.log(`  ${s.kind.padEnd(14)} ${s.id.padEnd(30)} ${s.publicUrl ?? `http://${config.host}:${s.port}`}${s.roles ? `  [${s.roles.join(', ')}]` : ''}`);
for (const a of config.authorities) console.log(`  ${a.kind.padEnd(14)} ${a.id}`);
