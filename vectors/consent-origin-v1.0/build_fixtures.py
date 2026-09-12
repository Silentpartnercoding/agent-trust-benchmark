"""Build and self-validate consent-origin adversarial fixtures for AEP v0.5.

Completeness is defined mechanically here, not asserted: every normative rule extracted from
the schema's own field descriptions must have at least one fixture that satisfies it and at
least one that breaks it. The script fails if any rule is uncovered in either direction.

The rules below are quoted from the published descriptions. None of them is expressible in
JSON Schema, and the published schema contains no cross-field keywords at all, so a record can
satisfy validation completely and still break every one of them.
"""

import json
import pathlib
from jsonschema import Draft202012Validator

HERE = pathlib.Path(__file__).parent
SCHEMA = json.loads((HERE / "aep-record.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA)

ORDER = ["unknown", "operator_asserted", "principal_key_signed", "qualified_signature"]
IDENTITY_RANK = {"unknown": 0, "self_asserted": 1, "organization_attested": 2,
                 "notified_eid": 3, "qualified_certificate": 4}

# ---------------------------------------------------------------- normative rules
# Each returns "holds", "violates", or "n/a" (rule not engaged by this record).


def r_floor_not_round_up(r):
    o, f = r.get("run_attribution_backing_observed"), r.get("run_attribution_backing_floor")
    if o is None or f is None or not o:
        return "n/a"
    return "holds" if f == min(o, key=ORDER.index) else "violates"


def r_floor_within_observed(r):
    o, f = r.get("run_attribution_backing_observed"), r.get("run_attribution_backing_floor")
    if o is None or f is None:
        return "n/a"
    return "holds" if f in o else "violates"


def r_floor_needs_observed(r):
    """'Report together with run_attribution_backing_observed, never instead of it.'"""
    if "run_attribution_backing_floor" not in r:
        return "n/a"
    o = r.get("run_attribution_backing_observed")
    return "holds" if o else "violates"


def r_observed_needs_floor(r):
    """'the itemization alone permits exactly the masking the floor exists to prevent'"""
    if "run_attribution_backing_observed" not in r:
        return "n/a"
    return "holds" if "run_attribution_backing_floor" in r else "violates"


def r_record_backing_within_run(r):
    """A record's own backing cannot be stronger than the strongest the run observed."""
    b, o = r.get("attribution_backing"), r.get("run_attribution_backing_observed")
    if b is None or not o:
        return "n/a"
    return "holds" if ORDER.index(b) <= ORDER.index(max(o, key=ORDER.index)) else "violates"


def r_identity_not_folded(r):
    """'NEVER folded into attribution_backing and never rounded up.'

    Violated when a strong identity source is used to justify a qualified backing grade with
    no signature basis: qualified_signature claimed while identity is merely attested.
    """
    b, i = r.get("attribution_backing"), r.get("identity_source")
    if b is None or i is None:
        return "n/a"
    if b == "qualified_signature" and IDENTITY_RANK.get(i, 0) < IDENTITY_RANK["notified_eid"]:
        return "violates"
    if r.get("_identity_upgraded_backing"):
        return "violates"
    return "holds"


def r_authorized_by_omitted_when_same(r):
    """'omit when the same principal did both.'"""
    a = r.get("authorized_by")
    if a is None:
        return "n/a"
    return "violates" if a == r.get("user_id") else "holds"


def r_origin_matches_authorizer(r):
    """administrator_assigned means no principal was prompted, so the subject cannot be the
    authorizer; organization_wide names no individual grantor."""
    o, a, u = r.get("authority_origin"), r.get("authorized_by"), r.get("user_id")
    if o is None:
        return "n/a"
    if o == "administrator_assigned" and a is not None and a == u:
        return "violates"
    if o == "organization_wide" and a is not None:
        return "violates"
    if o == "subject_consented" and a is not None and a != u:
        return "violates"
    return "holds"



def r_count_covers_observed(r):
    """'the floor MUST equal the weakest grade across that declared set' - the declared count
    cannot be smaller than the number of distinct grades already itemised."""
    c, o = r.get("authorization_evidence_count"), r.get("run_attribution_backing_observed")
    if c is None or o is None:
        return "n/a"
    return "holds" if c >= len(set(o)) else "violates"


RULES = {
    "floor-must-not-round-up": (r_floor_not_round_up,
        "The floor MUST NOT round up - one strong grant must not mask unbacked authorizations."),
    "floor-within-observed": (r_floor_within_observed,
        "A reported floor must be one of the grades actually observed."),
    "floor-requires-observed": (r_floor_needs_observed,
        "Report together with run_attribution_backing_observed, never instead of it."),
    "observed-requires-floor": (r_observed_needs_floor,
        "The itemization alone permits exactly the masking the floor exists to prevent."),
    "record-backing-within-run": (r_record_backing_within_run,
        "Producers MUST NOT report a stronger grade than the evidence supports."),
    "identity-never-folded": (r_identity_not_folded,
        "Identity source is reported verbatim, NEVER folded into attribution_backing."),
    "authorized-by-omitted-when-same": (r_authorized_by_omitted_when_same,
        "Omit authorized_by when the same principal initiated and authorized."),
    "count-covers-observed": (r_count_covers_observed,
        "A declared authorization_evidence_count cannot be smaller than the number of distinct "
        "grades already itemised in run_attribution_backing_observed."),
    "origin-consistent-with-authorizer": (r_origin_matches_authorizer,
        "administrator_assigned means no principal was prompted; organization_wide names no "
        "individual grantor; subject_consented means the subject approved."),
}


def base(run_id, **kw):
    rec = {"schema_version": "aep/v0.5", "run_id": run_id,
           "created_at_ms": 1757460000000, "user_id": "user-alice",
           "subject_id": "agent-filer-7"}
    rec.update(kw)
    return rec


F = []


def fx(id, intent, expect_schema, record, note=None):
    F.append(dict(id=id, intent=intent, expect_schema=expect_schema, record=record, note=note))


# ---- the motivating pair -------------------------------------------------------
fx("CO-101-ENTRA-CONSENTED",
   "Half of the Entra pair: a grant the human interactively approved.",
   "valid", base("run-co-101", authority_origin="subject_consented",
                 identity_source="organization_attested",
                 attribution_backing="operator_asserted"))
fx("CO-102-ENTRA-ADMIN",
   "The other half. Byte-identical in every identity claim, created administratively with no "
   "prompt ever shown. Only authority_origin separates them.",
   "valid", base("run-co-102", authorized_by="admin-bob",
                 authority_origin="administrator_assigned",
                 identity_source="organization_attested",
                 attribution_backing="operator_asserted"))

# ---- positive controls that must not be 'corrected' ----------------------------
fx("CO-103-EID-STILL-KEY-SIGNED",
   "The schema's own example: a device-key signature by an eID-proofed person is still "
   "principal_key_signed on the backing axis.",
   "valid", base("run-co-103", authority_origin="subject_consented",
                 identity_source="notified_eid",
                 attribution_backing="principal_key_signed"))
fx("CO-104-ORG-WIDE-NAMES-NOBODY",
   "Organization-wide consent. A human clicked, but no individual granted it, so authorized_by "
   "is absent rather than guessed.",
   "valid", base("run-co-104", authority_origin="organization_wide",
                 identity_source="organization_attested",
                 attribution_backing="operator_asserted"))
fx("CO-105-UNKNOWN-IS-A-CLAIM",
   "Provider exposes nothing. unknown is stated, which is a claim.",
   "valid", base("run-co-105", authority_origin="unknown", identity_source="unknown",
                 attribution_backing="unknown"))
fx("CO-106-ABSENT-IS-NOT-UNKNOWN",
   "The same run with the fields omitted entirely. Per the descriptions, absent means the "
   "producer makes no claim, which is not the same as unknown. A consumer that treats these "
   "two records as equivalent has lost the distinction both authors argued for.",
   "valid", base("run-co-106"),
   note="Compare against CO-105. Schema cannot distinguish them; a consumer must.")
fx("CO-107-FLOOR-HONEST",
   "Mixed run reported honestly: both grades itemised, floor is the weaker.",
   "valid", base("run-co-107", attribution_backing="qualified_signature",
                 run_attribution_backing_floor="operator_asserted",
                 run_attribution_backing_observed=["operator_asserted", "qualified_signature"]))

# ---- adversarial: schema-valid, rule-breaking ----------------------------------
fx("CO-201-FLOOR-ROUNDS-UP",
   "The anti-evasion case. A qualified grant masks an operator-asserted one by reporting the "
   "strongest as the floor.",
   "valid", base("run-co-201", authority_origin="subject_consented",
                 run_attribution_backing_floor="qualified_signature",
                 run_attribution_backing_observed=["operator_asserted", "qualified_signature"]))
fx("CO-202-UNKNOWN-MASKED",
   "An entirely unbacked authorization hidden behind a signed one. unknown is the weakest grade "
   "and the floor claims otherwise.",
   "valid", base("run-co-202", authority_origin="administrator_assigned",
                 run_attribution_backing_floor="principal_key_signed",
                 run_attribution_backing_observed=["unknown", "principal_key_signed"]))
fx("CO-203-FLOOR-NOT-OBSERVED",
   "Floor names a grade that appears nowhere in the itemisation.",
   "valid", base("run-co-203", run_attribution_backing_floor="operator_asserted",
                 run_attribution_backing_observed=["principal_key_signed"]))
fx("CO-204-FLOOR-WITHOUT-OBSERVED",
   "A floor reported instead of the itemisation, which the description forbids in those words. "
   "The floor alone loses that a strong authorization exists anywhere in the run.",
   "valid", base("run-co-204", run_attribution_backing_floor="operator_asserted"))
fx("CO-205-OBSERVED-WITHOUT-FLOOR",
   "The itemisation alone, which the description says permits exactly the masking the floor "
   "exists to prevent.",
   "valid", base("run-co-205",
                 run_attribution_backing_observed=["unknown", "qualified_signature"]))
fx("CO-206-FLOOR-OVER-EMPTY",
   "A floor asserted over an empty itemisation.",
   "valid", base("run-co-206", run_attribution_backing_floor="qualified_signature",
                 run_attribution_backing_observed=[]))
fx("CO-207-RECORD-BACKING-EXCEEDS-RUN",
   "The record claims a stronger grade for itself than any the run observed.",
   "valid", base("run-co-207", attribution_backing="qualified_signature",
                 run_attribution_backing_floor="operator_asserted",
                 run_attribution_backing_observed=["operator_asserted"]))
fx("CO-208-IDENTITY-FOLDED-INTO-BACKING",
   "A strong identity source used to justify a qualified backing grade with no signature basis. "
   "This is the fold the description forbids.",
   "valid", base("run-co-208", identity_source="organization_attested",
                 attribution_backing="qualified_signature"))
fx("CO-209-AUTHORIZED-BY-REDUNDANT",
   "authorized_by repeats user_id, which the description says to omit. Harmless alone, but it "
   "makes the requester/authorizer split unreadable across a corpus.",
   "valid", base("run-co-209", authorized_by="user-alice",
                 authority_origin="subject_consented"))
fx("CO-210-ADMIN-ASSIGNED-SELF-AUTHORIZED",
   "administrator_assigned means no principal was ever prompted, yet the subject is named as "
   "the authorizer.",
   "valid", base("run-co-210", authorized_by="user-alice",
                 authority_origin="administrator_assigned"))
fx("CO-211-ORG-WIDE-NAMES-A-GRANTOR",
   "organization_wide means consent was granted on behalf of an organization, so naming an "
   "individual grantor contradicts the origin.",
   "valid", base("run-co-211", authorized_by="admin-bob",
                 authority_origin="organization_wide"))
fx("CO-212-CONSENTED-BUT-SOMEONE-ELSE-AUTHORIZED",
   "subject_consented claims the principal approved, while a different party is recorded as "
   "the authorizer.",
   "valid", base("run-co-212", authorized_by="admin-bob",
                 authority_origin="subject_consented"))


# ---- the selective-omission defence he added on 12 September --------------------
fx("CO-108-COUNT-CONSISTENT",
   "The declared evidence population matches what is itemised, and the floor is the weakest of "
   "it. This is the shape the new count is for.",
   "valid", base("run-co-108", authorization_evidence_count=2,
                 run_attribution_backing_floor="operator_asserted",
                 run_attribution_backing_observed=["operator_asserted", "qualified_signature"]))
fx("CO-213-COUNT-SMALLER-THAN-ITEMISED",
   "The declared population is smaller than the number of distinct grades already listed, which "
   "cannot be true. Schema-valid because the two fields are unconnected.",
   "valid", base("run-co-213", authorization_evidence_count=1,
                 run_attribution_backing_floor="operator_asserted",
                 run_attribution_backing_observed=["operator_asserted", "qualified_signature"]))
fx("CO-214-COUNT-DECLARED-FLOOR-STILL-ROUNDS-UP",
   "A declared population does not by itself stop the rounding it was added to expose: the count "
   "is honest and the floor is still the strongest grade rather than the weakest.",
   "valid", base("run-co-214", authorization_evidence_count=2,
                 run_attribution_backing_floor="qualified_signature",
                 run_attribution_backing_observed=["operator_asserted", "qualified_signature"]))

# ---- schema-invalid: confirm validation catches what it can --------------------
fx("CO-301-STALE-ORIGIN-SPELLING",
   "The pre-rename spelling. An implementer working from the 9 September thread rather than "
   "the schema emits exactly this.",
   "invalid", base("run-co-301", authority_origin="admin_assigned"))
fx("CO-302-ORIGIN-VALUE-IN-BACKING",
   "Axis collapse: an origin concept written into the backing field.",
   "invalid", base("run-co-302", attribution_backing="subject_consented"))
fx("CO-303-QUALIFIED-CERTIFICATE-AS-BACKING",
   "The most likely honest mistake in the whole vocabulary: qualified_certificate is an "
   "identity_source value and qualified_signature is a backing value, one word apart.",
   "invalid", base("run-co-303", attribution_backing="qualified_certificate"))
fx("CO-304-SELF-ASSERTED-AS-BACKING",
   "Same near-miss on the other pair: self_asserted is identity, operator_asserted is backing.",
   "invalid", base("run-co-304", attribution_backing="self_asserted"))
fx("CO-305-BACKING-VALUE-IN-IDENTITY",
   "The reverse smuggle, to pin the boundary in both directions.",
   "invalid", base("run-co-305", identity_source="principal_key_signed"))


# ---------------------------------------------------------------- build + verify
def main():
    out, failures = [], []
    coverage = {k: {"holds": [], "violates": []} for k in RULES}

    for f in F:
        rec = {k: v for k, v in f["record"].items() if not k.startswith("_")}
        errs = sorted(VALIDATOR.iter_errors(rec), key=lambda e: list(e.path))
        schema_verdict = "valid" if not errs else "invalid"
        if schema_verdict != f["expect_schema"]:
            failures.append(f"{f['id']}: schema expected {f['expect_schema']}, got {schema_verdict}"
                            + (f" ({errs[0].message})" if errs else ""))

        verdicts = {}
        for name, (fn, _) in RULES.items():
            v = fn(f["record"])
            verdicts[name] = v
            if v in ("holds", "violates") and schema_verdict == "valid":
                coverage[name][v].append(f["id"])

        broken = [n for n, v in verdicts.items() if v == "violates"]
        out.append({
            "id": f["id"], "intent": f["intent"],
            **({"note": f["note"]} if f["note"] else {}),
            "record": rec,
            "schema_validation": {"expected": f["expect_schema"], "observed": schema_verdict,
                                  "first_error": errs[0].message if errs else None},
            "rules_broken": broken,
            "rule_verdicts": {n: v for n, v in verdicts.items() if v != "n/a"},
        })
        print(f"  {f['id']:<44} schema={schema_verdict:<8}"
              f"{'breaks: ' + ','.join(broken) if broken else 'clean'}")

    print("\n  rule coverage (schema-valid fixtures only):")
    for name in RULES:
        h, v = coverage[name]["holds"], coverage[name]["violates"]
        ok = bool(h) and bool(v)
        print(f"    {'ok  ' if ok else 'GAP '} {name:<36} holds={len(h)} violates={len(v)}")
        if not h:
            failures.append(f"coverage: no fixture SATISFIES {name}")
        if not v:
            failures.append(f"coverage: no fixture VIOLATES {name}")

    doc = {
        "schema": "consent-origin-adversarial-fixtures/1.0",
        "target": {"spec": "aep/v0.5", "schema_url": SCHEMA.get("$id"),
                   "validated_against": "schemas/aep/aep-record.schema.json as merged in "
                                        "WasmAgent/wasmagent-protocol#213"},
        "claim_boundary": (
            "These fixtures test whether a consumer preserves the evidenced origin of authority "
            "and reports the backing floor without rounding it up. They do not verify "
            "credentials, prove identity, or establish that a consent was legally sufficient."),
        "completeness_basis": (
            "Every normative rule stated in the v0.5 attribution field descriptions is listed "
            "below, and the generator fails unless each has at least one schema-valid fixture "
            "that satisfies it and one that breaks it. Completeness is claimed against that "
            "extracted rule set, not against all possible misuse."),
        "known_limit": (
            "One evasion is not detectable from a record at all: under-reporting "
            "run_attribution_backing_observed. Omitting a weak grade entirely leaves a record "
            "whose floor is honestly the weakest of what was listed. No fixture can catch this, "
            "because the missing grade leaves no trace. It is the same shape as the refusal-"
            "record completeness problem and needs a second party, not a schema."),
        "rules": {k: d for k, (_, d) in RULES.items()},
        "generated_by": "build_fixtures.py, which validates every record against the published "
                        "schema, re-derives every rule verdict, and fails on any uncovered rule",
        "fixtures": out,
    }
    (HERE / "fixtures.json").write_text(
        json.dumps(doc, indent=2) + "\n")

    print()
    if failures:
        print("SELF-CHECK FAILED:")
        for x in failures:
            print("   ", x)
        raise SystemExit(1)
    valid_broken = sum(1 for f in out if f["schema_validation"]["observed"] == "valid"
                       and f["rules_broken"])
    print(f"  {len(out)} fixtures, all matching expectation, {len(RULES)} rules all covered "
          f"both ways")
    print(f"  {valid_broken} pass schema validation while breaking at least one stated rule")
    print("  wrote fixtures.json")


if __name__ == "__main__":
    main()
