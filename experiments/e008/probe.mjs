/**
 * E008 — actor binding in an offline authorization-lineage verifier.
 *
 * Builds minimal VAL chains that differ only in how the grant names its actor, runs the
 * published verifier over each, and compares the verdict against an expectation recorded
 * in this file. Emits results/e008/<run-id>/result.json.
 *
 * Every arm is generated here; nothing is transcribed by hand. Run:
 *   npm ci && node probe.mjs
 */
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyValChain, reconstructChainHash } from '@val-protocol/chain-verifier';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..');
const VERIFIER_VERSION = JSON.parse(
  readFileSync(join(HERE, 'node_modules', '@val-protocol', 'chain-verifier', 'package.json')),
).version;

/** RFC 8785 JCS, sufficient for the ASCII objects below (sorted keys, no floats). */
const jcs = (v) => {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
};

const SCOPE_KEY = 'e008';

async function append(rows, eventType, body) {
  const previous_hash = rows.length ? rows[rows.length - 1].chain_hash : null;
  const sequence_number = rows.length + 1;
  const canonical_details = jcs(body);
  const chain_hash = await reconstructChainHash({
    scopeKey: SCOPE_KEY, sequenceNumber: sequence_number, eventType,
    canonicalDetails: canonical_details, previousHash: previous_hash,
  });
  rows.push({ scope_key: SCOPE_KEY, sequence_number, event_type: eventType,
              canonical_details, previous_hash, chain_hash });
  return chain_hash;
}

const HUMAN = {
  method: 'session',
  subject_user_hash: 'b'.repeat(64),
  attested_at: 1700000000,
  delegator_authority: { basis: 'operator:owner', capability: 'cap.read', scope_ref: 'ws-1' },
};
const GRANTED = 'agent:legit';
const IMPOSTOR = 'agent:impostor';
const RES = { in_workspace: 'ws-1' };
const withSubj = { act: ['read'], res: RES, subj: { principal_uri: GRANTED } };
const noSubj = { act: ['read'], res: RES };

async function buildAndVerify({ rootScope, rootV = 2, grantee, subScope, actor }) {
  const rows = [];
  const root = await append(rows, 'assignment.created', {
    v: rootV, block_type: 'ASSIGNMENT', scope: rootScope,
    ...(grantee ? { grantee } : {}), human_attestation: HUMAN,
  });
  let parent = root;
  if (subScope !== undefined) {
    parent = await append(rows, 'assignment.created', {
      v: 2, block_type: 'ASSIGNMENT', parent_assignment_hash: root,
      scope: subScope, human_attestation: HUMAN,
    });
  }
  await append(rows, 'record.accessed', {
    v: 1, block_type: 'ACCESS', parent_assignment_hash: parent, action: 'read',
    principal: actor,
    resource: { content_hash: 'a'.repeat(64), resource_id: 'doc-1', in_workspace: 'ws-1' },
  });
  return { rows, report: await verifyValChain(rows) };
}

/** Expectations are part of the artifact: an arm fails if the verifier disagrees. */
const ARMS = [
  { arm: 'root-subj-impostor', note: 'Root grant names the actor; a different agent acts.',
    cfg: { rootScope: withSubj, actor: IMPOSTOR }, expect: { scope: 'red', authority: 'green' } },
  { arm: 'root-subj-named-control', note: 'Control. The named agent acts.',
    cfg: { rootScope: withSubj, actor: GRANTED }, expect: { scope: 'green', authority: 'green' } },
  { arm: 'root-nosubj-impostor', note: 'Root grant omits the subject clause; a different agent acts.',
    cfg: { rootScope: noSubj, actor: IMPOSTOR }, expect: { scope: 'green', authority: 'green' } },
  { arm: 'root-nosubj-v3-grantee', note: 'No subject clause, but a v3 body carrying grantee.',
    cfg: { rootScope: noSubj, rootV: 3, grantee: GRANTED, actor: IMPOSTOR },
    expect: { scope: 'green', authority: 'red' } },
  { arm: 'sub-drops-subj', note: 'Sub-assignment omits the clause its root set.',
    cfg: { rootScope: withSubj, subScope: noSubj, actor: IMPOSTOR },
    expect: { scope: 'red', authority: 'green' } },
  { arm: 'sub-renames-subj', note: 'Sub-assignment names the impostor instead.',
    cfg: { rootScope: withSubj, subScope: { act: ['read'], res: RES, subj: { principal_uri: IMPOSTOR } }, actor: IMPOSTOR },
    expect: { scope: 'red', authority: 'green' } },
];

const started_at = new Date().toISOString();
const arms = [];
for (const a of ARMS) {
  const { rows, report } = await buildAndVerify(a.cfg);
  const observed = { scope: report.scope, authority: report.authority,
                     integrity: report.integrity, lineage: report.lineage };
  const matched = observed.scope === a.expect.scope && observed.authority === a.expect.authority;
  arms.push({
    arm: a.arm, note: a.note,
    assignment_body_version: a.cfg.rootV ?? 2,
    grant_names: a.cfg.grantee ?? a.cfg.rootScope.subj?.principal_uri ?? null,
    sub_assignment_names:
      a.cfg.subScope === undefined ? null : (a.cfg.subScope.subj?.principal_uri ?? null),
    acted_as: a.cfg.actor,
    expected: a.expect,
    observed,
    status: matched ? 'MATCHED' : 'DIVERGED',
    first_scope_violation: report.firstScopeViolation?.reason ?? null,
    first_authority_violation: report.firstAuthorityViolation?.reason ?? null,
    chain_hashes: rows.map((r) => r.chain_hash),
  });
}
const completed_at = new Date().toISOString();

const diverged = arms.filter((a) => a.status === 'DIVERGED');
const result = {
  schema_version: 'e008/v1',
  experiment_id: 'E008',
  run_id: 'e008-val-actor-binding-v1',
  status: 'exploratory',
  preregistered: false,
  disclosure:
    'The arms below were run during an investigation of a third-party claim and written up '
    + 'afterwards. They were not preregistered. The expectations recorded in probe.mjs were '
    + 'fixed before this file was generated, so a later change in the subject would surface as '
    + 'DIVERGED, but they cannot be counted as predictions made in advance of first observation.',
  subject: {
    implementation: '@val-protocol/chain-verifier',
    version: VERIFIER_VERSION,
    source: 'npm',
    protocol: 'VAL v0.1',
  },
  started_at,
  completed_at,
  arms,
  checks: [
    { check: 'ACTOR_BINDING_ENFORCED_WHEN_NAMED',
      status: arms.find((a) => a.arm === 'root-subj-impostor')?.observed.scope === 'red' ? 'PASS' : 'FAIL',
      detail: 'A grant naming its actor refuses an action by a different agent.' },
    { check: 'ACTOR_BINDING_SURVIVES_SUBDELEGATION',
      status: arms.filter((a) => a.arm.startsWith('sub-')).every((a) => a.observed.scope === 'red') ? 'PASS' : 'FAIL',
      detail: 'A sub-assignment can neither drop nor widen the subject clause its root established.' },
    { check: 'ACTOR_BINDING_PRESENT_BY_DEFAULT',
      status: arms.find((a) => a.arm === 'root-nosubj-impostor')?.observed.scope === 'red' ? 'PASS' : 'FAIL',
      detail: 'A root grant that omits the optional subject clause still binds the actor. '
            + 'FAIL records that it does not: every property verifies green for an unnamed agent.' },
  ],
  metrics: {
    ARMS_TOTAL: arms.length,
    ARMS_MATCHING_EXPECTATION: arms.length - diverged.length,
    ARMS_DIVERGED: diverged.length,
  },
};

const outDir = join(REPO, 'results', 'e008', result.run_id);
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, 'result.json'), JSON.stringify(result, null, 2) + '\n');

for (const a of arms) {
  console.log(`${a.status === 'MATCHED' ? 'ok  ' : 'DIFF'}  ${a.arm.padEnd(26)} scope=${a.observed.scope.padEnd(5)} authority=${a.observed.authority}`);
}
console.log(`\nverifier ${VERIFIER_VERSION} · ${arms.length} arms · ${diverged.length} diverged`);
console.log(`wrote ${join('results', 'e008', result.run_id, 'result.json')}`);
process.exit(diverged.length === 0 ? 0 : 1);
