# Dark Recon Framework — Differentiation Strategy
*Not another phase list. A bet on what actually makes it the best, and a plan to prove it.*

---

## The Thesis

Every recon framework converges on the same ~40 wrapped tools. Coverage is a solved problem — anyone can clone bbot or ReconFTW and get 80% of what a 300-item roadmap describes. Being "the best ever" isn't won by having more phases than competitors. It's won by being *right more often, faster, on the findings that actually pay*. This plan picks three narrow moats and starves everything else until they're real.

---

## The Three Moats (and only these, for now)

### Moat 1 — A confidence score nobody can fake
Most tools report findings. None credibly score them. Build a scoring model where the score is *earned*: independent tool agreement, historical accept-rate for that finding signature, and asset criticality — not a hardcoded severity label copied from a template. The test of success: your own triage time per finding drops, and your accept-rate on submissions goes up, because you stop chasing the score's false positives.

### Moat 2 — Business logic depth nothing else has
IDOR, auth-bypass, and race-condition chains require session state and multi-request reasoning — the one category where payload-scanners structurally cannot compete. This is the only track from the earlier 300-item plan worth fully building before anything else. One well-built stateful test engine here is worth more than the other 21 tracks combined.

### Moat 3 — A flywheel, not a snapshot
The framework should get smarter with every engagement, not just every code release. Every submission outcome (accepted / duped / informational / rejected) becomes training signal for the confidence model. Six months from now the tool should be measurably better calibrated than it is today, without you touching the roadmap — because the data did the work.

---

## The Anti-Feature List (deliberately not building these yet)

Saying no is the actual strategy. Explicitly deprioritized until the three moats are proven:

- Mobile, IoT, wireless, container/K8s deep coverage — extend surface area, don't build moat
- Dashboards, team collaboration, RBAC — organizational polish, not capability
- ML-assisted anything beyond the confidence model — premature; no flywheel data yet to train on
- Distributed/K8s scaling — scaling an unproven signal just produces false positives faster
- Compliance mapping (ASVS/PCI tagging) — useful later, irrelevant to whether findings are correct

If it doesn't make findings more accurate or business-logic coverage deeper, it waits.

---

## The Metric That Matters

One number, tracked from day one, above every other KPI:

**Findings submitted → accepted rate, weighted by severity, per scan-hour.**

Everything in the moats above should move this number. Everything on the anti-feature list, by design, does not move it — which is exactly why it waits. Track this per engagement, per program, and per finding-class, and let it — not intuition — decide what gets built next.

---

## Execution Order (by dependency, not by calendar)

1. **Schema + confidence model skeleton** — the minimum data structure needed to score anything at all
2. **Submission-outcome logging** — start capturing accept/dupe/reject on every existing manual submission *today*, even before automation exists, so the flywheel has data by the time Moat 1 ships
3. **Stateful session engine** — the reusable core that IDOR, auth-bypass, and race-condition testing all sit on top of
4. **IDOR test harness on the stateful engine** — first concrete proof the moat works
5. **Confidence model v1, trained on whatever outcome data exists by this point** — even 20–30 labeled outcomes beats a hardcoded severity table
6. **Re-measure the one metric** — did accept-rate per scan-hour actually move? If not, the moat isn't real yet — iterate here before adding anything else
7. Only after step 6 shows real movement: expand the stateful engine to auth-bypass and race conditions, and start layering in the wider surface coverage from the earlier 300-item plan, now guided by which finding classes the outcome data says actually pay

---

## Positioning

Don't market this as "covers the most attack surface." Market it — even just to yourself  — as: *"the framework that tells you which finding to chase first, and finds the logic bugs nothing else catches."* That's a claim you can actually defend with data six months from now. "300 phases" is not.

---

## What Changes This Time

Every prior plan optimized for completeness. This one optimizes for a single number going up. If accept-rate per scan-hour isn't moving, the plan is wrong regardless of how many phases are implemented — and that's the point: it's now falsifiable instead of just large.
