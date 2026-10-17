import payment from './01-payment.js';
import filing from './02-regulatory-filing.js';
import hf from './03-huggingface-replay.js';
import compute from './04-compute-pilot.js';
import federation from './05-federation.js';
import audit from './06-audit.js';
import lineage from './07-lineage-transfer.js';

export const scenarios = [payment, filing, hf, compute, federation, audit, lineage];
