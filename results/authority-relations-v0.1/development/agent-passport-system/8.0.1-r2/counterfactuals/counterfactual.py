#!/usr/bin/env python3
"""Counterfactual cases for the APS adapter revision 2, run against the old adapter
(8.0.1), the new adapter (8.0.1-r2, v0.1 reasons and native reasons) and the suite's
reference control adapters/relation_aware.py. Local only, nothing here is a benchmark
result. Each case is one change from a frozen v0.1 vector.

Usage: counterfactual.py ATB_ROOT  (prints a table, writes counterfactual-results.json beside this file)
ATB_ROOT is a checkout of the suite at the authority-relations-v0.1 tag with this results directory
in place. Run npm ci --ignore-scripts in 8.0.1/adapter and 8.0.1-r2/adapter first.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
VEC = ROOT / "vectors" / "authority-relations-v0.1"
DEV = ROOT / "results" / "authority-relations-v0.1" / "development" / "agent-passport-system"
OLD = DEV / "8.0.1" / "adapter" / "aps_adapter.mjs"
NEW = DEV / "8.0.1-r2" / "adapter" / "aps_adapter.mjs"
REF = ROOT / "adapters" / "relation_aware.py"  # the suite's reference control
FIELDS = ["status", "authorized", "reason", "evidence_status", "request_authority_valid",
          "execution_authority_valid", "derived_authority_relation", "request_authority_source",
          "execution_authority_source", "immediate_authority_grantor", "declared_relation_matches"]


def base(name):
    c = json.loads((VEC / f"{name}.json").read_text())
    c.pop("expected", None)
    return c


def mutate(name, fn, vid):
    c = base(name)
    fn(c)
    c["vector_id"] = vid
    return c


def o(c):
    return c["observed"]


def src_mismatch(c):
    o(c)["delegation"]["authority_source"] = "org:someone-else"


def valid_direct(c):
    ob = o(c)
    ob["execution_authority"].update(kind="EXECUTION", status="VALID", source="org:direct", subject=ob["actor"],
                                     action=dict(ob["requested_action"]), independently_issued=True)
    ob["declared_relation"] = "INDEPENDENT"
    if "INDEPENDENT" not in c["policy"]["allowed_relations"]:
        c["policy"]["allowed_relations"].append("INDEPENDENT")


def invalid_request(c):
    o(c)["request_authority"].update(status="INVALID", source="org:x", subject=o(c)["requester"], action=o(c)["requested_action"])


CASES = [
    ("CF-01", "REQUEST evidence MISSING, requester authority required, executor valid",
     mutate("unauthorized-requester", lambda c: None, "CF-01"), {}),
    ("CF-02", "REQUEST evidence INVALID, policy rejects invalid evidence",
     mutate("unauthorized-requester", invalid_request, "CF-02"), {}),
    ("CF-03", "REQUEST evidence INVALID, policy does NOT reject invalid evidence",
     mutate("unauthorized-requester", lambda c: (invalid_request(c), c["policy"].update(reject_invalid_evidence=False)), "CF-03"), {}),
    ("CF-04", "execution evidence VALID but independently_issued false, requester not required",
     mutate("permissionless-request", lambda c: o(c)["execution_authority"].update(independently_issued=False), "CF-04"), {}),
    ("CF-05", "revocation status unknown for every record",
     mutate("permissionless-request", lambda c: None, "CF-05"), {"ATB_APS_REVOCATION": "unknown"}),
    ("CF-06", "requester and executor both fail: REQUEST MISSING, execution INVALID, invalid evidence rejected",
     mutate("unauthorized-requester", lambda c: o(c)["execution_authority"].update(status="INVALID"), "CF-06"), {}),
    ("CF-07", "as CF-06, invalid evidence not rejected (precedence decides the reason)",
     mutate("unauthorized-requester", lambda c: (o(c)["execution_authority"].update(status="INVALID"), c["policy"].update(reject_invalid_evidence=False)), "CF-07"), {}),
    ("CF-08", "delegation VALID but the delegator holds no request authority (request MISSING)",
     mutate("delegation", lambda c: o(c)["request_authority"].update(status="MISSING"), "CF-08"), {}),
    ("CF-09", "VALID REQUEST evidence, requester authority NOT required",
     mutate("mandate", lambda c: c["policy"].update(requester_authority="NOT_REQUIRED"), "CF-09"), {}),
    ("CF-10", "INVALID delegation whose authority_source does not match the requester root",
     mutate("spoofed-delegation", src_mismatch, "CF-10"), {}),
    ("CF-11", "as CF-10, plus a valid independent execution path the policy and declaration allow",
     mutate("spoofed-delegation", lambda c: (src_mismatch(c), valid_direct(c)), "CF-11"), {}),
    ("CF-12", "execution item of kind REQUEST marked INVALID",
     mutate("permissionless-request", lambda c: o(c)["execution_authority"].update(kind="REQUEST", status="INVALID"), "CF-12"), {}),
    ("CF-13", "requester root grant broader than the requested action (target '*')",
     mutate("delegation", lambda c: o(c)["request_authority"]["action"].update(target="*"), "CF-13"), {}),
    ("CF-14", "as CF-13, requester authority NOT required",
     mutate("delegation", lambda c: (o(c)["request_authority"]["action"].update(target="*"), c["policy"].update(requester_authority="NOT_REQUIRED")), "CF-14"), {}),
]


def run_aps(path, case, env):
    e = dict(os.environ, **env)
    p = subprocess.run(["node", str(path)], input=json.dumps(case).encode(), capture_output=True, env=e, cwd=path.parent)
    out = json.loads(p.stdout) if p.stdout else {"status": "ERROR", "reason": p.stderr.decode()[-300:]}
    prov = [l for l in p.stderr.decode().splitlines() if l.startswith("PROVENANCE ")]
    return out, (json.loads(prov[0][11:]) if prov else None)


def run_ref(case):
    p = subprocess.run([sys.executable, "-I", str(REF)], input=json.dumps(case).encode(), capture_output=True)
    return json.loads(p.stdout)


def diff(a, ref):
    if a.get("status") != "DECIDED":
        return [a.get("status")]
    keys = sorted((set(ref) | set(a)) - {"status"})
    return [f for f in keys if a.get(f) != ref.get(f)]  # every output field, not only FIELDS


def main():
    rows = []
    for cid, desc, case, env in CASES:
        ref = run_ref(case)
        old, _ = run_aps(OLD, case, env)
        new, prov = run_aps(NEW, case, env)
        nat, _ = run_aps(NEW, case, dict(env, ATB_APS_REASONS="native"))
        rows.append({"id": cid, "desc": desc, "env": env, "ref": ref, "old": old, "new": new, "new_native": nat,
                     "old_vs_ref": diff(old, ref), "new_vs_ref": diff(new, ref), "native_vs_ref": diff(nat, ref),
                     "provenance": prov})
        print(f"{cid} {desc}")
        print(f"   ref  {ref['authorized']!s:5} {ref['reason']}")
        print(f"   old  {old['status']:11} {str(old.get('authorized')):5} {old['reason'][:62]}  diff={diff(old, ref)}")
        print(f"   new  {new['status']:11} {str(new.get('authorized')):5} {new['reason'][:62]}  diff={diff(new, ref)}")
        print(f"   nat  reason={nat['reason'][:62]}  diff={diff(nat, ref)}")
    (Path(__file__).resolve().parent / "counterfactual-results.json").write_text(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
