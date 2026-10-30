// ATB authority-relations-v0.1 transport adapter for the agent-passport-system SDK, revision 2.
//
// Reads one atb-authority-relation-case/0.1 object on stdin and writes one
// atb-authority-relation-output/0.1 object on stdout. Diagnostics and a decision
// provenance record go to stderr. The output schema allows no extra fields.
//
// What the SDK decides and what this adapter decides are kept apart:
//
//   SDK (agent-passport-system 8.0.1): signature, continuity, trust root, time and
//   revocation checks on each AuthorityDelegationV1 chain (verifyAuthorityDelegationChain),
//   and whether a grant covers the requested action (scopeGrantCovers).
//
//   Adapter: how the benchmark's evidence statuses become records, the relation label,
//   the benchmark's policy switches, its `independently_issued` input flag, and the
//   v0.1 reason precedence. None of these is APS verification semantics.
//
// Changes from revision 1 (8.0.1):
//   1. UNSUPPORTED only when the output would have to state that REQUEST-kind authority
//      is valid. APS has no record for authority to request an action apart from
//      authority to execute it, and the output schema makes request_authority_valid a
//      boolean, so a VALID REQUEST item cannot be answered honestly. A MISSING or INVALID
//      REQUEST item can: no valid request authority was presented.
//   2. An SDK result of `indeterminate` is no longer folded into INVALID. v0.1 has no
//      slot for "could not decide", so the adapter returns UNSUPPORTED with the SDK codes.
//   3. `independently_issued` is read as a benchmark input condition. `false` blocks the
//      independent execution path. `true` only satisfies the benchmark's condition, it is
//      supplied test data and is not verified by the SDK.
//   4. Reasons follow the v0.1 precedence. ATB_APS_REASONS=native keeps the APS labels,
//      so a comparison can show which matches come only from the reason translation.
//   5. A delegation whose delegator holds no valid EXECUTION authority is "no valid
//      delegation path", not invalid evidence. Invalid evidence comes only from items the
//      benchmark marks INVALID or from an SDK `invalid` result.
//
// ATB_APS_REVOCATION=unknown makes the revocation resolver answer `unknown`. It exists
// only for the counterfactual tests of the indeterminate path. Benchmark runs leave it unset.

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
const REASONS = process.env.ATB_APS_REASONS === 'native' ? 'native' : 'v01';
const REVOCATION = process.env.ATB_APS_REVOCATION === 'unknown' ? 'unknown' : 'active';

const input = JSON.parse(readFileSync(0, 'utf8'));
const { vector_id: vectorId, policy, observed } = input;
const requester = observed.requester;
const actor = observed.actor;
const ra = observed.request_authority;
const ea = observed.execution_authority;
const dg = observed.delegation;
const action = observed.requested_action;

const provenance = []; // one entry per decision step: { step, by: 'sdk' | 'adapter' | 'input', detail }
function prov(step, by, detail) {
  provenance.push({ step, by, detail });
}
function log(msg) {
  process.stderr.write(`[aps-adapter-r2 ${vectorId}] ${msg}\n`);
}

function grantOf(a) {
  return `${a.resource}:${a.action}:${a.target}`;
}
function sameAction(a, b) {
  return a && b && a.resource === b.resource && a.action === b.action && a.target === b.target;
}
const requiredGrant = grantOf(action);

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
  return { ...record, signature: (sig[0] === '0' ? '1' : '0') + sig.slice(1) };
}

const trustedRoots = new Set([ra.source, ea.source, dg.authority_source].filter((s) => typeof s === 'string' && s));
const verifyOptions = {
  now: NOW,
  resolveVerificationKey: (issuer) => (keys.has(issuer) ? keys.get(issuer).publicKey : null),
  trustRoot: (root) => trustedRoots.has(root.issuer),
  resolveRevocation: () => REVOCATION,
};
function issueRoot(evidence, label, depth) {
  const rec = issueAuthorityDelegation(
    body({ parent: null, issuer: evidence.source, subject: evidence.subject, grants: [grantOf(evidence.action)], depth, label }),
    keyFor(evidence.source).privateKey,
  );
  return evidence.status === 'INVALID' ? corrupt(rec) : rec;
}
function verify(label, chain) {
  const res = verifyAuthorityDelegationChain(chain, verifyOptions);
  const codes = res.failures.map((f) => f.code);
  prov(`${label}:chain`, 'sdk', `${res.state}${codes.length ? ' ' + codes.join(',') : ''}`);
  return { state: res.state, codes };
}

function emit(fields) {
  process.stderr.write(`PROVENANCE ${JSON.stringify({ vector_id: vectorId, reasons: REASONS, revocation: REVOCATION, steps: provenance })}\n`);
  process.stdout.write(JSON.stringify({ schema: OUTPUT_SCHEMA, vector_id: vectorId, requester, actor, ...fields }));
  process.exit(0);
}
function unsupported(why) {
  prov('outcome', 'adapter', `UNSUPPORTED: ${why}`);
  log(`UNSUPPORTED: ${why}`);
  emit({
    status: 'UNSUPPORTED',
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
    reason: `APS_UNSUPPORTED: ${why}`,
  });
}

// --- 1. Request authority -----------------------------------------------------------------
// The output must state request_authority_valid as a boolean. For a VALID item of kind
// REQUEST that would mean asserting authority APS cannot represent, so stop here.

let requestValid = false;
let requestSource = null;
let requesterRoot = null; // an APS root grant to the requester, kind EXECUTION only
let requestInvalid = false;

if (ra.kind === 'REQUEST') {
  if (ra.status === 'VALID') {
    unsupported(
      'a VALID request-authority item of kind REQUEST would have to be reported as valid or not. APS has no record ' +
        'for authority to request an action apart from authority to execute it, so it cannot establish either answer',
    );
  }
  if (ra.status === 'INVALID') requestInvalid = true;
  prov('request', 'input', `kind REQUEST, status ${ra.status}: no valid request authority presented`);
} else if (ra.kind === 'EXECUTION') {
  if (ra.status === 'MISSING') {
    prov('request', 'input', 'kind EXECUTION, status MISSING: no valid request authority presented');
  } else {
    requesterRoot = issueRoot(ra, 'request-authority', 1);
    const r = verify('request', [requesterRoot]);
    if (r.state === 'indeterminate') unsupported(`request-authority chain indeterminate (${r.codes.join(',')})`);
    if (r.state === 'invalid') requestInvalid = true;
    const fits = requesterRoot.subject === requester && sameAction(ra.action, action);
    prov('request:binding', 'adapter', `subject is requester and action matches: ${fits}`);
    requestValid = r.state === 'valid' && fits;
    if (r.state !== 'valid') requesterRoot = null;
    if (requestValid) requestSource = ra.source;
  }
} else {
  unsupported(`unknown request-authority kind ${JSON.stringify(ra.kind)}`);
}

// --- 2. Execution authority: delegated path ---------------------------------------------

let delegationValid = false;
let delegationInvalid = false;
let delegationLeaf = null;
if (dg.status === 'MISSING') {
  prov('delegation', 'input', 'status MISSING');
} else if (dg.status === 'INVALID' && !requesterRoot) {
  delegationInvalid = true;
  prov('delegation', 'input', 'status INVALID, no parent record to verify it against');
} else if (!requestValid || !requesterRoot || dg.delegator !== requester || requesterRoot.issuer !== dg.authority_source) {
  prov('delegation', 'adapter', 'no valid EXECUTION authority held by the delegator: no delegated path, not invalid evidence');
} else {
  const childGrants = dg.attenuated === true ? [grantOf(dg.action)] : [`${dg.action.resource}:*`];
  let child = null;
  try {
    child = issueSubAuthorityDelegation(
      requesterRoot,
      body({ parent: requesterRoot, issuer: dg.delegator, subject: dg.delegatee, grants: childGrants, depth: 0, label: 'delegation' }),
      keyFor(dg.delegator).privateKey,
      { now: NOW, resolveVerificationKey: verifyOptions.resolveVerificationKey, resolveRevocation: verifyOptions.resolveRevocation },
    );
  } catch (err) {
    const code = err && err.code ? err.code : 'ISSUE_REFUSED';
    prov('delegation:issue', 'sdk', `issueSubAuthorityDelegation refused: ${code}`);
    if (REVOCATION === 'unknown') unsupported(`delegation could not be issued while revocation status is unknown (${code})`);
  }
  if (child) {
    if (dg.status === 'INVALID') child = corrupt(child);
    const r = verify('delegation', [requesterRoot, child]);
    if (r.state === 'indeterminate') unsupported(`delegation chain indeterminate (${r.codes.join(',')})`);
    if (r.state === 'invalid') delegationInvalid = true;
    const covers = child.authority.scope.grants.some((g) => scopeGrantCovers(g, requiredGrant));
    prov('delegation:scope', 'sdk', `scopeGrantCovers: ${covers}`);
    const fits = child.subject === actor && sameAction(dg.action, action) && dg.attenuated === true;
    prov('delegation:binding', 'adapter', `delegatee is actor, action matches, attenuated: ${fits}`);
    delegationValid = r.state === 'valid' && covers && fits;
    if (delegationValid) delegationLeaf = child;
  }
}

// --- 3. Execution authority: independent path -------------------------------------------

let directValid = false;
let executionInvalid = false;
if (ea.status === 'MISSING') {
  prov('execution', 'input', 'status MISSING');
} else if (ea.kind !== 'EXECUTION') {
  prov('execution', 'adapter', `kind ${ea.kind} is not execution authority`);
} else {
  const root = issueRoot(ea, 'execution-authority', 0);
  const r = verify('execution', [root]);
  if (r.state === 'invalid') executionInvalid = true;
  const covers = root.authority.scope.grants.some((g) => scopeGrantCovers(g, requiredGrant));
  prov('execution:scope', 'sdk', `scopeGrantCovers: ${covers}`);
  const fits = root.subject === actor && sameAction(ea.action, action);
  prov('execution:binding', 'adapter', `subject is actor and action matches: ${fits}`);
  const independent = ea.independently_issued === true;
  prov('execution:independently_issued', 'input', `${ea.independently_issued} (benchmark-supplied, not verified by the SDK)`);
  if (r.state === 'indeterminate' && !delegationValid) unsupported(`execution-authority chain indeterminate (${r.codes.join(',')})`);
  directValid = r.state === 'valid' && covers && fits && independent;
}

// --- 4. Relation and policy (adapter) ------------------------------------------------------

let relation = 'NONE';
let execSource = null;
let grantor = null;
if (delegationValid) {
  relation = 'DELEGATED';
  execSource = requesterRoot.issuer;
  grantor = delegationLeaf.issuer;
} else if (directValid) {
  relation = 'INDEPENDENT';
  execSource = ea.source;
  grantor = ea.source;
}
const executionValid = relation !== 'NONE';
prov('relation', 'adapter', relation);

const suppliedInvalid = [ra, ea, dg].some((item) => item.status === 'INVALID');
prov('evidence:invalid-status', 'input', `any supplied item marked INVALID: ${suppliedInvalid}`);
const anyInvalid = suppliedInvalid || requestInvalid || delegationInvalid || executionInvalid;
const evidenceStatus = anyInvalid ? 'INVALID' : executionValid ? 'VERIFIED' : 'INCOMPLETE';
const declared = observed.declared_relation;
const declaredMatches = declared === null ? null : declared === relation;
const requesterRequired = policy.requester_authority === 'REQUIRED';

const evidenceOk = !policy.reject_invalid_evidence || evidenceStatus !== 'INVALID';
const requestOk = requestValid || !requesterRequired;
const relationOk = policy.allowed_relations.includes(relation);
const declarationOk = !policy.require_declared_relation_match || declaredMatches === true;
const authorized = evidenceOk && requestOk && executionValid && relationOk && declarationOk;

// v0.1 precedence, with the native APS label beside each code.
let v01;
let native;
if (!evidenceOk) {
  v01 = 'INVALID_EVIDENCE';
  native = 'APS_EVIDENCE_INVALID';
} else if (!requestOk) {
  v01 = 'REQUEST_AUTHORITY_REQUIRED';
  native = 'APS_REQUESTER_AUTHORITY_NOT_VERIFIED';
} else if (!executionValid) {
  v01 = 'EXECUTION_AUTHORITY_INVALID';
  native = 'APS_NO_VALID_CHAIN_FOR_ACTOR';
} else if (!relationOk) {
  v01 = 'RELATION_NOT_ALLOWED';
  native = `APS_RELATION_NOT_ALLOWED:${relation}`;
} else if (!declarationOk) {
  v01 = 'RELATIONSHIP_MISMATCH';
  native = `APS_DECLARED_RELATION_MISMATCH:${declared}->${relation}`;
} else if (!requesterRequired) {
  v01 = 'EXECUTOR_AUTHORITY_VERIFIED_PERMISSIONLESS_REQUEST';
  native = relation === 'DELEGATED' ? 'APS_CHAIN_VALID_DELEGATED' : 'APS_CHAIN_VALID_ROOT_GRANT';
} else if (relation === 'DELEGATED') {
  v01 = 'VALID_DELEGATION';
  native = 'APS_CHAIN_VALID_DELEGATED';
} else {
  v01 = 'VALID_INDEPENDENT_AUTHORITY_PATHS';
  native = 'APS_CHAIN_VALID_ROOT_GRANT';
}
prov('reason', 'adapter', `v0.1 precedence: ${v01}, native label: ${native}`);

emit({
  status: 'DECIDED',
  evidence_status: evidenceStatus,
  declared_relation: declared,
  declared_relation_matches: declaredMatches,
  request_authority_source: requestSource,
  request_authority_valid: requestValid,
  execution_authority_source: execSource,
  immediate_authority_grantor: grantor,
  execution_authority_valid: executionValid,
  derived_authority_relation: relation,
  policy_profile: policy.profile,
  requester_authority_required: requesterRequired,
  authorized,
  reason: REASONS === 'native' ? native : v01,
});
