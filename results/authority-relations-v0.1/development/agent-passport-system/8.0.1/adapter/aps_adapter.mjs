// ATB authority-relations-v0.1 transport adapter for the agent-passport-system SDK.
//
// Reads one atb-authority-relation-case/0.1 object on stdin and writes one
// atb-authority-relation-output/0.1 object on stdout. Diagnostics go to stderr.
//
// The case carries post-verification evidence statuses. The adapter materializes
// each piece of evidence as a native APS AuthorityDelegationV1 record (draft-03
// path): VALID evidence is issued and signed normally, INVALID evidence is issued
// and then has its signature corrupted, MISSING evidence produces no record. The
// SDK's verifyAuthorityDelegationChain and scopeGrantCovers then decide whether
// the actor holds authority for the requested action. The relation is read from
// the shape of the verified chain: a one-record chain issued straight to the actor
// is a root grant (INDEPENDENT), a multi-record chain is a delegation (DELEGATED).
//
// APS has no record type for authority to *request* an action that is separate
// from authority to *execute* it. When the supplied policy requires requester
// authority and the case expresses that authority as kind REQUEST, the adapter
// returns UNSUPPORTED with the reason on stderr.

import {
  generateKeyPair,
  issueAuthorityDelegation,
  issueSubAuthorityDelegation,
  verifyAuthorityDelegationChain,
  scopeGrantCovers,
} from 'agent-passport-system';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const OUTPUT_SCHEMA = 'atb-authority-relation-output/0.1';

const input = JSON.parse(readFileSync(0, 'utf8'));
const { vector_id: vectorId, policy, observed } = input;
const requester = observed.requester;
const actor = observed.actor;
const ra = observed.request_authority;
const ea = observed.execution_authority;
const dg = observed.delegation;

function log(msg) {
  process.stderr.write(`[aps-adapter ${vectorId}] ${msg}\n`);
}

function grantOf(action) {
  return `${action.resource}:${action.action}:${action.target}`;
}

const requiredGrant = grantOf(observed.requested_action);

// Fixed clock so every record and every check sees the same instant.
const NOW = '2026-10-29T12:00:00.000Z';
const ISSUED_AT = '2026-10-29T11:00:00.000Z';
const NOT_BEFORE = ISSUED_AT;
const NOT_AFTER = '2026-10-29T14:00:00.000Z';

const keys = new Map();
function keyFor(name) {
  if (!keys.has(name)) keys.set(name, generateKeyPair());
  return keys.get(name);
}

function nonceFor(label) {
  return createHash('sha256').update(`${vectorId}|${label}`).digest('hex').slice(0, 32);
}

function body({ parent, issuer, subject, grants, depth, label }) {
  return {
    record_type: 'aps:authority-delegation:v1',
    version: '1.0',
    parent_delegation_id: parent ? parent.delegation_id : null,
    issuer,
    subject,
    verification_method: `${issuer}#key-1`,
    issued_at: ISSUED_AT,
    nonce: nonceFor(label),
    authority: {
      scope: { profile: 'aps-hierarchical-v1', grants },
      spend: { mode: 'unbounded' },
      depth: { remaining: depth },
      time: { not_before: NOT_BEFORE, not_after: NOT_AFTER },
      reputation: { profile: 'aps-score-0-100-v1', ceiling: 100 },
      values: { profile: 'aps-values-identifiers-v1', required: [] },
      reversibility: { profile: 'aps-tci-v1', ceiling: 'irreversible' },
    },
  };
}

function corrupt(record) {
  const sig = record.signature;
  const flipped = (sig[0] === '0' ? '1' : '0') + sig.slice(1);
  return { ...record, signature: flipped };
}

// Trust policy: the roots named as authority sources in the supplied evidence.
const trustedRoots = new Set(
  [ra.source, ea.source, dg.authority_source].filter((s) => typeof s === 'string'),
);

const verifyOptions = {
  now: NOW,
  resolveVerificationKey: (issuer) => (keys.has(issuer) ? keys.get(issuer).publicKey : null),
  trustRoot: (root) => trustedRoots.has(root.issuer),
  resolveRevocation: () => 'active',
};

function issueRoot(evidence, label, depth) {
  const rec = issueAuthorityDelegation(
    body({ parent: null, issuer: evidence.source, subject: evidence.subject, grants: [grantOf(evidence.action)], depth, label }),
    keyFor(evidence.source).privateKey,
  );
  return evidence.status === 'INVALID' ? corrupt(rec) : rec;
}

function unsupported(reason) {
  log(`UNSUPPORTED: ${reason}`);
  process.stdout.write(
    JSON.stringify({
      schema: OUTPUT_SCHEMA,
      status: 'UNSUPPORTED',
      vector_id: vectorId,
      requester,
      actor,
      evidence_status: 'INCOMPLETE',
      declared_relation: observed.declared_relation,
      declared_relation_matches: null,
      request_authority_source: null,
      request_authority_valid: false,
      execution_authority_source: null,
      immediate_authority_grantor: null,
      execution_authority_valid: false,
      derived_authority_relation: 'NONE',
      policy_profile: policy.profile,
      requester_authority_required: policy.requester_authority === 'REQUIRED',
      authorized: false,
      reason: `APS_UNSUPPORTED: ${reason}`,
    }),
  );
  process.exit(0);
}

if (policy.requester_authority === 'REQUIRED' && ra.kind === 'REQUEST') {
  unsupported(
    'policy requires requester authority of kind REQUEST; APS models only authority held by the actor ' +
      '(a delegation chain from a trusted root to the subject that executes). It has no record type for ' +
      'authority to request an action separate from authority to execute it.',
  );
}

// --- Materialize evidence as native records -------------------------------------------

const presented = []; // every record or chain presented, with its SDK verification result

// Requester's own authority. Only kind EXECUTION is representable (an APS root grant to A).
let requesterRoot = null;
if (ra.kind === 'EXECUTION' && ra.status !== 'MISSING') {
  requesterRoot = issueRoot(ra, 'request-authority', 1);
}

// Candidate chains proving the actor's authority.
const actorChains = [];

if (ea.status !== 'MISSING') {
  actorChains.push({ label: 'execution-authority', chain: [issueRoot(ea, 'execution-authority', 0)] });
}

if (dg.status !== 'MISSING') {
  const parent = requesterRoot;
  if (!parent || parent.subject !== dg.delegator || parent.issuer !== dg.authority_source) {
    log('delegation presented without a parent record for its delegator; chain cannot be formed');
    presented.push({ label: 'delegation', state: 'invalid', failures: [{ code: 'CHAIN_CONTINUITY' }] });
  } else {
    const childGrants = dg.attenuated ? [grantOf(dg.action)] : [`${dg.action.resource}:*`];
    let child = null;
    try {
      child = issueSubAuthorityDelegation(
        parent,
        body({ parent, issuer: dg.delegator, subject: dg.delegatee, grants: childGrants, depth: 0, label: 'delegation' }),
        keyFor(dg.delegator).privateKey,
        { now: NOW, resolveVerificationKey: verifyOptions.resolveVerificationKey, resolveRevocation: () => 'active' },
      );
    } catch (err) {
      log(`issueSubAuthorityDelegation refused: ${err && err.code ? err.code : err}`);
      presented.push({ label: 'delegation', state: 'invalid', failures: [{ code: err && err.code ? err.code : 'ISSUE_REFUSED' }] });
    }
    if (child) {
      if (dg.status === 'INVALID') child = corrupt(child);
      actorChains.push({ label: 'delegation', chain: [parent, child] });
    }
  }
}

// --- Native verification ----------------------------------------------------------------

let requesterResult = null;
if (requesterRoot) {
  requesterResult = verifyAuthorityDelegationChain([requesterRoot], verifyOptions);
  presented.push({ label: 'request-authority', state: requesterResult.state, failures: requesterResult.failures });
  log(`request-authority chain: ${requesterResult.state} ${JSON.stringify(requesterResult.failures.map((f) => f.code))}`);
}

let accepted = null;
for (const candidate of actorChains) {
  const res = verifyAuthorityDelegationChain(candidate.chain, verifyOptions);
  const leaf = candidate.chain[candidate.chain.length - 1];
  const covers = leaf.authority.scope.grants.some((g) => scopeGrantCovers(g, requiredGrant));
  const forActor = leaf.subject === actor;
  presented.push({ label: candidate.label, state: res.state, failures: res.failures });
  log(
    `${candidate.label} chain: ${res.state} ${JSON.stringify(res.failures.map((f) => f.code))} ` +
      `subject_is_actor=${forActor} scope_covers=${covers}`,
  );
  if (res.valid && forActor && covers && !accepted) accepted = { ...candidate, leaf };
}

// --- Translate SDK results into the output schema ------------------------------------

const anyInvalid = presented.some((p) => p.state !== 'valid');
const evidenceStatus = anyInvalid ? 'INVALID' : accepted ? 'VERIFIED' : 'INCOMPLETE';

let derived = 'NONE';
let execSource = null;
let grantor = null;
if (accepted) {
  const root = accepted.chain[0];
  execSource = root.issuer;
  grantor = accepted.leaf.issuer;
  derived = accepted.chain.length > 1 || root.issuer === requester ? 'DELEGATED' : 'INDEPENDENT';
}

const requesterValid = Boolean(
  requesterResult && requesterResult.valid && requesterRoot.subject === requester,
);
const declared = observed.declared_relation;
const declaredMatches = declared === null ? null : declared === derived;
const requesterRequired = policy.requester_authority === 'REQUIRED';

// Policy as supplied by the case. APS supplies the evidence verdicts above; these four
// knobs are the case's policy and have no single native APS counterpart.
let authorized = false;
let reason;
if (policy.reject_invalid_evidence && evidenceStatus === 'INVALID') {
  const codes = presented.filter((p) => p.state !== 'valid').flatMap((p) => p.failures.map((f) => f.code));
  reason = `APS_EVIDENCE_INVALID:${[...new Set(codes)].join(',')}`;
} else if (!accepted) {
  reason = 'APS_NO_VALID_CHAIN_FOR_ACTOR';
} else if (requesterRequired && !requesterValid) {
  reason = 'APS_REQUESTER_AUTHORITY_NOT_VERIFIED';
} else if (!policy.allowed_relations.includes(derived)) {
  reason = `APS_RELATION_NOT_ALLOWED:${derived}`;
} else if (policy.require_declared_relation_match && declaredMatches !== true) {
  reason = `APS_DECLARED_RELATION_MISMATCH:${declared}->${derived}`;
} else {
  authorized = true;
  reason = derived === 'DELEGATED' ? 'APS_CHAIN_VALID_DELEGATED' : 'APS_CHAIN_VALID_ROOT_GRANT';
}

process.stdout.write(
  JSON.stringify({
    schema: OUTPUT_SCHEMA,
    status: 'DECIDED',
    vector_id: vectorId,
    requester,
    actor,
    evidence_status: evidenceStatus,
    declared_relation: declared,
    declared_relation_matches: declaredMatches,
    request_authority_source: requesterRoot ? requesterRoot.issuer : null,
    request_authority_valid: requesterValid,
    execution_authority_source: execSource,
    immediate_authority_grantor: grantor,
    execution_authority_valid: Boolean(accepted),
    derived_authority_relation: derived,
    policy_profile: policy.profile,
    requester_authority_required: requesterRequired,
    authorized,
    reason,
  }),
);
