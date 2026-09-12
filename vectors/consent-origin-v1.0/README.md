# Consent-origin adversarial fixtures, v1.0

Twenty-seven records targeting the attribution vocabulary in `aep/v0.5`
(`WasmAgent/wasmagent-protocol`), built at the request of that spec's maintainer.

The point of the set is a gap between what the published schema enforces and what it states.
Enum membership and array uniqueness are enforced. Every normative sentence in the attribution
field descriptions is not, and the schema carries no cross-field keywords at all. Fourteen of
these records therefore validate cleanly against the published schema while breaking a rule the
schema itself states.

Completeness is mechanical rather than asserted. Every normative rule extracted from those field
descriptions is listed in `fixtures.json`, and `build_fixtures.py` refuses to emit unless each
rule has at least one record that satisfies it and one that breaks it.

One evasion is out of reach of any record: under-reporting the itemised grades. The maintainer
added `authorization_evidence_count` on 12 September to commit a producer to a population;
three fixtures exercise it, and the README of the fixture file records why a declared count is
weaker than a derived one.

Reproduce:

    pip install jsonschema
    python build_fixtures.py

The schema copy here is pinned for reproducibility. Re-fetch it from the upstream repository to
check the set against a newer revision; the generator will fail loudly if a record's validity or
a rule verdict changes.
