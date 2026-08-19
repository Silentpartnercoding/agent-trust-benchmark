# Which directory is this?

This is a **clone of the public repository**
`github.com/Silentpartnercoding/agent-trust-benchmark`. Everything here is public
or will be on the next push. Work on the benchmark happens here.

The sibling directory `agent-trust-benchmark` is **not** a clone of this. It is a
private working directory holding material that has never been published — the
nxtlinq adapter and its run, the E004 comparative analysis, and E004/E005 docs
referencing Minority Prophet Border internals. It carries its own
`DO-NOT-PUBLISH.md` and a `pre-push` hook. Do not treat the two as
interchangeable, and do not copy files between them without checking which side
of that line they belong on.

If this copy has drifted behind origin, `git pull` rather than editing from a
stale base. Two separate incidents on 2026-08-18 and 2026-08-19 came from reading
a stale working copy and reporting it as the published state.
