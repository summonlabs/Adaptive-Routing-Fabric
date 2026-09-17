# Adaptive Routing Fabric

Adaptive Routing Fabric is the evidence-driven path-selection adaptation and controlled
transition runtime of the Distributed Fabric Infrastructure / Fabric OS stack.

It answers one question, and only that question:

> Given an already-governed set of currently legal candidate paths, current routing state,
> explicit adaptation policy, and current telemetry/evidence, should traffic-selection
> intent change now, which exact path or path set should become preferred, by how much,
> under which generation and authority, and when must an adaptation be suppressed,
> fenced, rolled back, revalidated, or rejected as stale?

Adaptive Routing Fabric owns the decision and the controlled preference-transition layer.
It does not own paths, legality, routes, membership, equal-cost assignment, explicit
weighting, convergence or global optimisation. Those belong to its neighbours, and it
never overrides any of them.

## Table of contents

- [What Adaptive Routing Fabric is](#what-adaptive-routing-fabric-is)
- [The exact boundary](#the-exact-boundary)
- [Relationships to neighbouring runtimes](#relationships-to-neighbouring-runtimes)
- [Policy identity and scope](#policy-identity-and-scope)
- [Policy lifecycle](#policy-lifecycle)
- [Evidence model](#evidence-model)
- [Evidence provenance](#evidence-provenance)
- [Evidence currentness](#evidence-currentness)
- [Metric representation](#metric-representation)
- [Trigger semantics](#trigger-semantics)
- [Hysteresis](#hysteresis)
- [Hold-down](#hold-down)
- [Cooldown](#cooldown)
- [Dampening](#dampening)
- [Bounded churn](#bounded-churn)
- [Candidate eligibility](#candidate-eligibility)
- [Deterministic ranking and tie-breaking](#deterministic-ranking-and-tie-breaking)
- [Objective and scoring versioning](#objective-and-scoring-versioning)
- [Generations](#generations)
- [Authority, epochs and fencing](#authority-epochs-and-fencing)
- [Two-phase evaluation and stale-decision fencing](#two-phase-evaluation-and-stale-decision-fencing)
- [Invalidation watermarks](#invalidation-watermarks)
- [Suppression outcomes](#suppression-outcomes)
- [Rollback](#rollback)
- [Revocation and retirement](#revocation-and-retirement)
- [Snapshots, diffs and explanations](#snapshots-diffs-and-explanations)
- [Deterministic digests](#deterministic-digests)
- [Persistence](#persistence)
- [Conservative recovery](#conservative-recovery)
- [Distributed process model](#distributed-process-model)
- [Resource limits](#resource-limits)
- [Deterministic rejection precedence](#deterministic-rejection-precedence)
- [REAL, SYNTHETIC and UNSUPPORTED validation](#real-synthetic-and-unsupported-validation)
- [Build](#build)
- [Test](#test)
- [Install and find_package](#install-and-find_package)
- [Command line tools](#command-line-tools)
- [Examples](#examples)
- [Benchmarks](#benchmarks)
- [Genuine limitations](#genuine-limitations)
- [License](#license)

## What Adaptive Routing Fabric is

The runtime is a single C++20 library with a small, explicit surface:

- **Adaptation policy** is a first-class governed object with a stable identity, an explicit
  scope, a lifecycle, a generation, and fully declared semantics.
- **Evidence** enters through a bounded, provenance-bound publication. It is never
  fabricated, never collected here, and never treated as authority merely because it is
  recent.
- **A decision** binds the policy generation, the route generation, the exact path
  authority generation of every candidate, the multipath generation, the evidence
  generation, the invalidation watermarks, the governing epoch and the authority
  generation that produced it.
- **A preference** is *intent*. It is not a route installation, not forwarding state and
  not convergence. The desired-versus-applied distinction is structural: no type in this
  runtime represents applied state.
- **A transition** is a bounded, local statement of what Adaptive Routing Fabric wants the
  route-visible preference to become. Route Convergence owns what happens next.

The runtime is deliberately narrow. A policy targets exactly one route. Wider change is
expressed by more policies, each independently authorized, and by the runtimes downstream.

## The exact boundary

Adaptive Routing Fabric owns:

- adaptation-policy identity, scope, lifecycle and generations;
- evidence-bound adaptation decisions and their authority binding;
- explicit thresholds, hysteresis, hold-down, cooldown and bounded dampening;
- minimum evidence requirements and evidence freshness requirements;
- candidate eligibility over an explicit candidate set;
- deterministic candidate ranking and canonical tie-breaking;
- current and desired routing preference, and the bounded transition between them;
- adaptation, transition and authority generations;
- stale-decision rejection, stale-evidence rejection and adaptation suppression;
- rollback intent and recovery to a revalidated prior preference;
- currentness, provenance, fencing, revalidation, snapshots, diffs, explanations;
- deterministic semantic and decision digests;
- versioned integrity-checked persistence and conservative restart recovery;
- distributed mutation authority with real worker-death and coordinator-restart proof.

Adaptive Routing Fabric does not own, and does not implement:

- canonical entity identity, topology or graph structure;
- live link-state truth, port configuration, capability truth or failure-domain truth;
- Fabric Epoch issuance;
- candidate path computation (no Dijkstra, no Yen, no internal search, no invented
  candidates);
- exact path legality;
- authoritative route lifecycle;
- multipath set membership;
- ECMP bucket ownership or equal-cost assignment;
- explicit non-equal path weighting;
- ordered multi-device update sequencing, loop-free update planning, network-wide
  make-before-break, convergence completion tracking or global stabilisation;
- global multi-commodity optimisation across many routes, demands and capacities;
- telemetry collection, congestion measurement, queue control, admission control,
  bandwidth reservation or physical switch programming;
- consensus, and any claim of split-brain prevention between isolated coordinators;
- cryptographic authentication of peers.

## Relationships to neighbouring runtimes

| Runtime | Owns | What Adaptive Routing Fabric does |
| --- | --- | --- |
| Fabric Registry | identity | references identities it is given; mints none of theirs |
| Fabric Topology | graph structure | never traverses a graph |
| Link State Fabric | operational link state | never observes a link directly |
| Port Fabric | port configuration | never configures a port |
| Fabric Capability Registry | capability truth | never asserts a capability |
| Failure Domain Registry | correlated-failure truth | consumes no diversity computation |
| Fabric Epoch | epoch authority | binds the epoch it is told is current and rejects every other |
| Path Planner | candidate computation | consumes already-computed candidates; never searches |
| Path Authority | exact path legality | binds an exact PathAuthorityGeneration and never overrides a denial |
| Route Fabric | route lifecycle | produces a desired preference transition; Route Fabric decides what changes |
| Multipath Fabric | simultaneous-use membership | chooses within an exact current member set; never adds or removes a member |
| ECMP Governor | equal-cost assignment | performs no ECMP mutation at all |
| Weighted Path Fabric | explicit weighting | *proposes* weights as intent; never commits a weight policy |
| Route Convergence | convergence sequencing | stops at "preference should change"; plans no sequencing |
| Traffic Engineering | global optimisation | solves no multi-commodity problem |
| Telemetry | collection | consumes narrow, explicit evidence contracts |

## Policy identity and scope

An `AdaptivePolicy` has a stable `AdaptivePolicyId`, a unique
`AdaptivePolicyName`, a `PolicyScope`, a `PolicySemantics` value, a
`AdaptivePolicyGeneration`, a `PolicyLifecycle`, the creating publisher and the
authority generation it was authored under. The identity is stable across ordinary
mutation; change is expressed by advancing the generation.

`PolicyScope` is default deny:

- a fabric and a routing namespace are mandatory;
- an optional site and an optional path class narrow it further; an unknown site never
  satisfies a site-restricted scope;
- an empty route list means "every route in this namespace", never "every route
  everywhere";
- an empty multipath-set list means the same for sets.

A publisher may only author a policy whose scope is inside its own registered authority
scope, and may only mutate policies whose scope its authority covers.

## Policy lifecycle

| State | ACTIVATE | SUSPEND | RESUME | REQUIRE_REVALIDATION | REVALIDATE | REVOKE | SUPERSEDE | RETIRE |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| DECLARED | ACTIVE | – | – | REVALIDATION_REQUIRED | – | REVOKED | SUPERSEDED | RETIRED |
| ACTIVE | – | SUSPENDED | – | REVALIDATION_REQUIRED | – | REVOKED | SUPERSEDED | RETIRED |
| SUSPENDED | – | – | ACTIVE | REVALIDATION_REQUIRED | – | REVOKED | SUPERSEDED | RETIRED |
| REVALIDATION_REQUIRED | – | SUSPENDED | – | – | ACTIVE | REVOKED | SUPERSEDED | RETIRED |
| REVOKED | – | – | – | – | – | – | – | – |
| SUPERSEDED | – | – | – | – | – | – | – | – |
| RETIRED | – | – | – | – | – | – | – | – |

Every cell is exercised by the test suite. REVOKE, SUPERSEDE and RETIRE are terminal: a
revoked, superseded or retired policy never reactivates, and every later lifecycle event
is refused with REVOKED, POLICY_SUPERSEDED or RETIRED respectively.

Only ACTIVE policies adapt. Decisions have their own, separate lifecycle
(PROPOSED, ELIGIBLE, SUPPRESSED, COMMITTED, SUPERSEDED, ROLLED_BACK,
REVALIDATION_REQUIRED, EXPIRED, REJECTED) with its own complete transition table, so the
existence of a decision is never confused with the authority to commit it.

## Evidence model

Evidence enters through `publish_evidence`, one bounded batch at a time. A publication
binds:

- an `EvidenceSourceId` and an `EvidenceSourceGeneration`;
- a declared `EvidenceQuality` class (PRIMARY, AGGREGATED, OPERATOR, ESTIMATED);
- the exact `PathId` the sample is about;
- a bounded `MetricValue`;
- a publisher-supplied, strictly increasing `observation_sequence`.

Rules the runtime enforces:

- a batch is validated **in full** before a single sample is applied, so a refused batch
  leaves no partial state;
- evidence may only be published for a path some policy inside the caller's authority
  scope actually binds;
- a source generation that goes backwards is STALE_EVIDENCE;
- a forward source generation drops the retained samples of the old incarnation and
  advances the evidence watermark — samples from two incarnations are never mixed;
- a refusal to increase the observation sequence is STALE_EVIDENCE;
- a quality change inside one source generation is refused; quality may only change
  together with a source generation;
- retention is bounded by `Limits::max_evidence_samples_per_series`, oldest first;
- a whole batch advances the evidence generation exactly once, and a rejected batch
  advances nothing.

Aggregation is deterministic and exact: MINIMUM, MAXIMUM, MEAN (floor of a checked signed
sum), MEDIAN and PERCENTILE_95 (nearest-rank order statistics over a deterministic
ascending sort), and EWMA (fixed-point, seeded with the first sample in observation order,
`ewma = floor((alpha*sample + (10000-alpha)*ewma) / 10000)`). Samples are aggregated in
observation order, so arrival order never changes a result.

## Evidence provenance

Every policy declares exactly which evidence it needs:

```
EvidenceRequirement {
  kind, aggregation, ewma_alpha_bps,
  min_samples, max_age, min_window, min_quality, required
}
```

A freshness bound is mandatory: `max_age` of zero is rejected rather than treated as
"unbounded", because a policy that omits it would let arbitrarily old evidence trigger a
routing change. `min_window` may not exceed `max_age`. `ewma_alpha_bps` is only
meaningful for EWMA and must be zero for every other aggregation. A duplicate requirement
for one metric is rejected, and every metric named by a trigger or by the objective must
have a declared requirement — otherwise the trigger could never be evaluated from declared
data.

## Evidence currentness

Freshness is not authority. A sample is usable only when its source generation is current,
its scope matches, its quality meets the declared minimum, and its age and observation
window satisfy the declared limits. A required metric that is absent or stale makes the
candidate ineligible: missing required evidence fails closed, and the runtime never claims
an evidence-driven superiority it cannot prove. An optional metric that is absent does not
block adaptation.

## Metric representation

Every authoritative metric is an exact integer in a declared unit, tagged with the
semantics version it was produced under, and bounded by the metric's own range. There is no
floating-point representation anywhere in the library, so NaN and infinity cannot enter
policy state, a digest, persistence or the wire.

| Metric kind | Unit | Orientation | Provenance | Range |
| --- | --- | --- | --- | --- |
| PATH_UTILIZATION | BASIS_POINTS | lower is better | MEASURED | 0..10000 |
| LINK_UTILIZATION | BASIS_POINTS | lower is better | MEASURED | 0..10000 |
| PATH_LATENCY | MICROSECONDS | lower is better | MEASURED | 0..4000000000 |
| QUEUE_PRESSURE | BASIS_POINTS | lower is better | MEASURED | 0..10000 |
| PACKET_LOSS | PPM | lower is better | MEASURED | 0..1000000 |
| ERROR_RATE | PPM | lower is better | MEASURED | 0..1000000 |
| HEALTH_DEGRADATION | BASIS_POINTS | lower is better | COMPUTED | 0..10000 |
| CONGESTION_SCORE | BASIS_POINTS | lower is better | COMPUTED | 0..10000 |
| PATH_QUALITY | BASIS_POINTS | higher is better | COMPUTED | 0..10000 |
| OPERATOR_POLICY_SIGNAL | FLAG | higher is better | OPERATOR_DECLARED | 0..1 |

Two values are comparable only when kind, unit and semantics version all match; anything
else is a structured INCOMPATIBLE_METRIC rejection rather than a silent coercion. All
arithmetic is checked: an overflowing aggregate or score is refused, never wrapped.

## Trigger semantics

A policy with no trigger condition is rejected at creation: a policy that could never adapt
must not be accepted and then silently do nothing. Two trigger forms exist and both are
explicit.

**Relative improvement.** `ImprovementRule { kind, switch_improvement_bps,
reverse_improvement_bps }`. A challenger must beat the current preference by at least
`switch_improvement_bps`; the *previously displaced* path must beat the incumbents by at
least `reverse_improvement_bps` to come back. Improvement is computed exactly, in basis
points, with floor rounding:

```
improvement = floor(|current - candidate| * 10000 / |current|)   when the candidate is better
            = 0                                                   otherwise
            = 10000                                               when |current| is zero
                                                                  and the candidate is strictly better
```

**Band threshold.** `ThresholdRule { kind, switch_value, clear_value }`. The current
preference may be left only when its value is at least as bad as `switch_value`, and a
challenger may be entered only when its value is at least as good as `clear_value`. For a
lower-is-better metric that means `value >= switch_value` to leave and `value <=
clear_value` to enter, so a well-formed band requires `clear_value < switch_value`. An
inverted or degenerate band is rejected as INVALID_HYSTERESIS, at creation time, never at
evaluation time.

## Hysteresis

Hysteresis is what stops threshold oscillation. The asymmetric reverse requirement is the
core of it: A to B is strictly easier than B back to A.

The specification's scenario, which the test suite drives exactly:

- A is preferred at 1000 µs; B is at 800 µs. The switch requirement is 20 %, so
  `floor(200 * 10000 / 1000) = 2000` bps meets it exactly and the adaptation commits.
- B is at 810 µs — 1900 bps, below the requirement — and nothing moves.
- A improves to 800 µs against B at 1000 µs: that is 2000 bps, but a *reverse* move needs
  30 % (3000 bps), so it is suppressed with HYSTERESIS_NOT_CLEARED.
- A improves to 600 µs: 4000 bps clears the reverse requirement and the preference returns.
- Feeding evidence that oscillates around 20 % from then on is suppressed every time.

## Hold-down

After a committed adaptation, an ordinary reverse adaptation is suppressed for the declared
interval. "Reverse" is precise: the target of the adaptation is the path the current
preference displaced. Suppression is reported as HOLD_DOWN_ACTIVE with the remaining
interval, and it advances no generation.

Hold-down is never implicit. A duration of zero disables it.

**Establishing the very first preference is not an adaptation.** There is nothing to
reverse, no churn has occurred and no oscillation is possible, so the establishing commit
arms no hold-down, arms no cooldown and consumes no churn budget. Every later commit is an
adaptation and arms all three.

## Cooldown

Cooldown is a separate rule with a separate meaning: after a committed adaptation, *no*
new ordinary adaptation is accepted for the interval, in any direction. Hold-down forbids
the reverse direction; cooldown forbids every ordinary direction. They are configured
independently and both are reported with their own outcome.

## Dampening

Repeated oscillation raises a bounded integer penalty that raises the effective hold-down:

```
penalty            = min(max_penalty, penalty + penalty_increment)      on every adaptation
effective_hold_down = min(duration + penalty * hold_down_escalation_step,
                          max_effective_hold_down)
```

There is no unbounded hidden state: the penalty is capped by `max_penalty`, the extension
by `max_effective_hold_down`, and a disabled dampening that carries active escalation
parameters is rejected as half-configured. When the extension is what suppressed an
adaptation, the reason is DAMPENING_EXTENDED_HOLD_DOWN rather than HOLD_DOWN_ACTIVE.

## Bounded churn

`ChurnBounds { max_adaptations_per_window, window }` counts committed adaptations inside a
sliding monotonic window. When the budget is exhausted the adaptation is suppressed with
CHURN_LIMIT_REACHED and the incumbent keeps its place. A bound without a window is
rejected. The configured bound is additionally capped by
`Limits::max_adaptations_per_window`.

## Candidate eligibility

Adaptation operates only over an explicit candidate set, bound per policy through
`UpstreamNotification`. There is no implicit discovery of any kind, and a candidate is
declared only together with a current legal Path Authority binding.

A candidate participates only when every one of these holds:

- its exact `PathAuthorityGeneration` is current and says the path is legally usable;
- its route binding is current;
- it is not upstream-unavailable;
- when the policy targets a multipath set: the set binding is current, names the same set
  as the policy target, and contains the path;
- every **required** evidence requirement is present, meets the declared quality, sample
  count, age and window limits;
- every objective term can be computed from declared evidence.

The first failure is reported per candidate on the recorded decision ranking, so
"why was this candidate rejected" is always answerable.

## Deterministic ranking and tie-breaking

Candidates are ordered by a total, canonical order:

1. **eligibility** — an eligible candidate always outranks an ineligible one; eligibility is
   a gate, not a preference, so a high-priority path that fails path authority never
   outranks one that passed;
2. **explicit policy priority**, higher first;
3. **weakest evidence quality actually used**, stronger first — a candidate scored from
   weak samples does not outrank one scored from strong samples;
4. **objective** — lexicographic terms in declared order, or the weighted score;
5. **canonical `PathId` byte order**.

No arrival order, thread schedule, random device, current time or pointer value ever
influences the result. The same state produces the same decision, and the test suite
asserts byte-identical decision digests across two independent engines.

## Objective and scoring versioning

`ObjectiveSpec` is either LEXICOGRAPHIC (terms compared in declaration order; weights must
be zero, because a silently ignored field is a defect) or WEIGHTED_SCORE (weights must be
non-zero and must sum to exactly 10000). Duplicate terms, missing terms and an unsupported
scoring version are rejected.

The weighted score is exact:

```
normalise(value) = floor(goodness * 10000 / (maximum - minimum))
score            = (sum(weight_i * normalise(value_i)) + 5000) / 10000     rounded half up
```

Every decision and every digest binds `scoring_version`. A scoring change requires a
different version, so two decisions produced by different formulas never compare as
identical authority. The representation versions are:

| Version | Value | Contract |
| --- | --- | --- |
| library / package / CLI | 1.0.0 | `version.hpp` |
| persistence format | 1 | on-disk encoding |
| wire protocol | 1 | framed transport |
| policy semantics | 1 | policy meaning |
| scoring algorithm | 1 | weighted score formula |
| digest encoding | 1 | canonical digest bytes |

A product release does not bump a representation version. A peer or a store that announces
a different representation version is rejected unread.

## Generations

| Generation | Advances when |
| --- | --- |
| `AdaptivePolicyGeneration` | policy semantics or scope change |
| `AdaptationGeneration` | semantic adaptive intent changes (a committed decision) |
| `TransitionGeneration` | desired transition content changes |
| `EvidenceGeneration` | an accepted evidence batch is applied |
| `AuthorityGeneration` | epoch, publisher incarnation, ownership transfer or recovery |
| `CoordinatorEpoch` | coordinator restart or explicit ownership transfer |

Reads, exact replays, unchanged evaluations and suppressed triggers advance nothing. All
advancement is checked: an exhausted counter produces GENERATION_OVERFLOW rather than
wrapping to zero. Generation zero is never valid, and the tests assert that a generation at
the top of its range has no successor.

## Authority, epochs and fencing

Exactly one coordinator owns mutation authority for a deployment. Adaptive Routing Fabric
does not implement consensus and does not claim split-brain prevention between isolated
coordinators. What it does implement is mandatory stale-epoch, stale-worker and
stale-generation rejection.

Every authoritative mutation binds a `CoordinatorEpoch`, a `PublisherId`, a
`WorkerBootId`, a `SessionId`, an authority scope, the expected generations and a
`MutationAttemptId`.

- Being connected is not authority.
- Being a known publisher is not authority.
- Having a durable policy record is not authority.

A restarted publisher receives a fresh `WorkerBootId`, and the previous incarnation is
fenced permanently: it can never publish evidence, commit an adaptation, modify a policy or
restore a stale preference again. A fenced boot can never re-register. An epoch advance
fences **every** live worker, clears the attempt table and moves every non-terminal policy
to REVALIDATION_REQUIRED.

`MutationAttemptId` gives idempotency: an exact replay returns IDEMPOTENT and changes
nothing; the same attempt id with a different payload is ATTEMPT_CONFLICT.

## Two-phase evaluation and stale-decision fencing

Evaluation runs in two phases, and only the second one can change anything.

1. **Phase one** takes a shared lock, validates caller identity, epoch, worker authority,
   scope, lifecycle and expected generations, then copies the policy, its candidates, the
   aggregated evidence and every generation and watermark into a `DependencySnapshot`.
   The lock is released. Evaluation runs lock-free. No I/O, no callback and no mutation
   happens under the write lock.
2. **Phase two** takes the exclusive lock and re-verifies everything before committing
   atomically: policy existence, epoch, authority generation, lifecycle, policy generation,
   evidence generation, evidence watermark and the precise dependency fingerprint of every
   candidate. Only then does it advance the generations and install the new preference.

The mandatory races, all driven deterministically by the test suite:

- an evaluation that started on evidence generation E must not commit after E+1 arrived;
- a candidate whose Path Authority moved from generation 7 to 8 must not become preferred
  under generation 7;
- an evaluation under policy generation 4 must not commit after the policy moved to 5;
- an evaluation under epoch N must not commit after epoch N+1 became current;
- a worker whose incarnation was fenced can neither publish nor commit;
- a retired policy refuses an in-flight evaluation;
- two tickets taken from the same state cannot both advance the adaptation generation.

Each rejection names the exact stale dependency. There is also a concurrency proof: several
threads mutating independent policies through a `std::barrier`-driven interleaving leave
every index consistent.

## Invalidation watermarks

Every path carries a monotonic invalidation watermark, advanced by every upstream event
that can invalidate a decision which already selected that path. An evaluation ticket
records the watermarks it observed; commit refuses when any of them moved.

Invalidation is targeted through reverse indexes: a path invalidation touches only the
policies that actually bind that path, never every policy. An unrelated path invalidation
leaves a policy's digest, preference and currentness exactly as they were, which the tests
assert directly.

The same indexes answer the operator's version of that question, without scanning every
policy: `policies_for_path`, `policies_for_route`, `policies_for_multipath_set` and
`policies_for_evidence_source` return the policies that depend on an upstream fact, in
canonical policy-id order. A test drives randomized schedules and asserts every one of
those answers equals a full scan of the same state, so an index cannot silently drift.

## Suppression outcomes

"No change" is never reported without a reason. Every suppressed decision carries both a
coarse `Outcome` and a precise `SuppressionReason`:

BELOW_THRESHOLD, HYSTERESIS_NOT_CLEARED, REVERSE_REQUIREMENT_NOT_MET, HOLD_DOWN_ACTIVE,
DAMPENING_EXTENDED_HOLD_DOWN, COOLDOWN_ACTIVE, INSUFFICIENT_SAMPLES, EVIDENCE_UNKNOWN,
STALE_EVIDENCE, NO_ELIGIBLE_ALTERNATIVE, CURRENT_PREFERENCE_INELIGIBLE,
UPSTREAM_DEPENDENCY_STALE, CHURN_LIMIT_REACHED, MERIT_NOT_ESTABLISHED,
NO_TRIGGER_DECLARED, POLICY_NOT_ACTIVE, POLICY_SUSPENDED, POLICY_REVOKED, POLICY_RETIRED,
REVALIDATION_REQUIRED.

A suppressed evaluation is still recorded as a decision with its full ranking, so an
operator can see exactly which candidate lost, by how much, and against which threshold.

## Rollback

Rollback is not "undo blindly". `StableState` records the last preference that was *held*
with matching dependencies — that is, the preference the current one displaced. It is the
rollback anchor, and establishing the first preference leaves no anchor at all.

A rollback revalidates the anchor against current Path Authority, route currency,
availability and multipath membership **before** any short circuit, and refuses with
STALE_PATH_AUTHORITY, STALE_ROUTE, STALE_MULTIPATH_SET or WITHDRAWN_UPSTREAM when the
anchor is no longer legitimate. On success it moves the anchor to the preference it
displaced, so rollback is a revalidated step back rather than a jump into the past.

## Revocation and retirement

Revocation is durable, idempotent, generation-bound and reason-coded (ADMINISTRATIVE,
SECURITY, POLICY_VIOLATION, AUTHORITY_REVOKED, OPERATOR_REQUEST). It is distinct from
evidence invalidation, from suspension and from retirement: revoking a policy does not
discard the evidence the runtime holds, and it survives persistence. A revoked policy
never adapts again.

Retirement is a lifecycle transition to a terminal state. A retired policy never
reactivates and never adapts again.

## Snapshots, diffs and explanations

A snapshot is an immutable point-in-time view of one policy, returned by value: the policy
identity, scope, lifecycle, generation, complete semantics, current preference, the
rollback anchor, every candidate with its eligibility and score, the evidence bindings, the
currentness verdict and its blockers, hold-down/cooldown state with remaining intervals,
the dampening penalty, every generation and watermark, the bounded history and the semantic
digest. Snapshot construction retains the snapshot in a bounded history.

A diff between two snapshots is deterministic: entries are ordered by (kind, field), so the
same pair of snapshots always renders identically. Twelve diff classes are produced:
policy change, lifecycle change, candidate eligibility change, evidence generation change,
preferred path change, adaptation suppressed, hold-down entered/exited, cooldown
entered/exited, authority change, currentness change, stable-state change, dampening change
and transition change.

Explanations answer twelve operator questions from the actual recorded state, not from a
narrative: why routing adapted, why it did not, which evidence crossed a threshold, which
evidence was stale, which candidate was rejected and why, why candidate B beat A, which
hysteresis threshold applied, whether hold-down is active, which generation made a prior
decision stale, why a rollback was refused, which publisher owns authority and which epoch
governs a decision. Explanation construction is bounded by
`Limits::max_explanation_entries`; at the bound the last entry becomes an explicit
truncation marker, and a bound of zero retains nothing.

## Deterministic digests

The digest is a deterministic, non-cryptographic hash used for integrity, change detection
and stale-decision comparison. It is not a signature, it is not a MAC, and it provides no
authentication.

- **Policy semantic digest** covers identity, name, scope, complete semantics, lifecycle and
  generation.
- **Decision digest** covers the policy identity and generation, lifecycle, cause, outcome,
  suppression reason, epoch, authority generation, route and route generation, multipath
  set and generation, evidence generation, watermarks, current and target preference with
  their authority generations, adaptation and transition generations, scoring version and
  the full canonical ranking. It excludes the decision id, evaluation id, evidence snapshot
  id, worker boot id, mutation attempt id, monotonic timestamps and derived counters, so
  the same inputs produce the same digest on every machine and every run.
- **Snapshot digest** covers the policy's own semantic state and its own dependencies —
  including each candidate's path authority generation, route generation, multipath
  generation and per-path invalidation watermark. The engine-global evidence generation and
  invalidation watermarks are deliberately excluded, because they move whenever any policy
  changes; including them would make a policy's digest change without that policy changing.
  This is what makes "unrelated activity leaves this policy unchanged" a testable property.

## Persistence

Persistence is versioned, integrity-checked, deterministic and bounded. It stores policies,
revocations, the last committed adaptive intent, the last known stable intent, bounded
adaptation history, invalidation watermarks and the restart-safe remainder of
hold-down/cooldown/dampening state.

Format: magic `ARFP`, format version, then length-prefixed records bounded individually
by `Limits::max_persistence_record_bytes` and collectively by
`Limits::max_store_bytes`, then an integrity trailer over everything before it. Writing is
atomic: bytes go to a sibling temporary file, are flushed, and are then moved over the
destination, so a crash mid-save leaves either the old store or the new one.

It does **not** store live process authority. No worker boot incarnation, no session
identity, no live registration, and no evidence samples survive a restart. Rejections are
specific: EMPTY, BAD_MAGIC, BAD_VERSION, TRUNCATED, INTEGRITY, MALFORMED, TRAILING_BYTES,
DUPLICATE_POLICY, INVALID_GENERATION, IMPOSSIBLE_LIFECYCLE, MALFORMED_METRIC,
MALFORMED_EVIDENCE_BINDING, INVALID_PREFERRED_CANDIDATE, TIMING_WITHOUT_POLICY,
ABSURD_COUNT, COUNTER_OVERFLOW, TOO_LARGE and MALFORMED_TIMING. The test suite attacks
every one of them, including every truncation prefix of a real store.

## Conservative recovery

Raw monotonic ticks are never serialised: they are meaningless in a different boot.
Durable timing is stored as a **remaining** duration plus the semantic decision it belongs
to, and is re-armed against the new boot's monotonic clock — which can extend an interval,
never shorten it.

Recovery is conservative by construction:

- policies are recovered, with their generation, scope and semantics;
- revocations are recovered and stay in force;
- the last committed intent and the rollback anchor are recovered as historical fact;
- recovery **consumes the next epoch**: a store written at epoch N reloads with epoch N+1;
- the authority generation advances;
- no publisher registration survives, so a pre-restart context is refused;
- **no evidence is restored**, so every evidence-dependent currentness is conservative from
  the first moment;
- every non-terminal policy becomes REVALIDATION_REQUIRED and returns to service only when
  revalidation actually succeeds.

Repeated save/load cycles advance the epoch monotonically, which the tests assert.

## Distributed process model

The distributed model is real. A coordinator process owns authority; publisher processes
connect to it over loopback TCP using a framed, versioned, integrity-checked protocol.
Sessions are OS sockets, worker death is an OS process termination and coordinator restart
is a real process restart against the same store.

Frame layout: a 32-byte header (magic, wire version, message id, flags, payload length,
sequence, epoch), the payload, and an 8-byte integrity trailer covering the semantic header
and the payload together. A payload that declares an absurd length is rejected before any
allocation; a frame with trailing bytes is rejected; an unknown enum is rejected; a zero
generation is rejected; the reader must consume the whole payload.

Twenty-three stable numeric message identifiers exist: HELLO, HELLO_ACK, REGISTER_PUBLISHER,
FENCE_NOTICE, CREATE_POLICY, UPDATE_POLICY, POLICY_LIFECYCLE, REVOKE_POLICY, UPSTREAM_NOTIFY,
PUBLISH_EVIDENCE, EVALUATE, COMMIT_DECISION, REVALIDATE, ROLLBACK, QUERY_STATE,
SNAPSHOT_REQUEST, SNAPSHOT_RESPONSE, EXPLAIN_REQUEST, DIFF_REQUEST, ADVANCE_EPOCH, RESULT,
ERROR, BYE.

A peer that sends a partial frame cannot pin a session forever: the receive loop is bounded
by `Limits::max_receive_stall_millis` on the monotonic clock, and exceeding it fails that
session explicitly while the coordinator keeps serving everyone else. On Windows a blocked
`recv` is not reliably cancelled by `shutdown()`, so the loop is built on a polling wait
with an explicit stop flag and sockets are closed only by their owner.

The worker-death and coordinator-restart proofs run against the shipped
`arf_coordinator` and `arf_publisher` executables, with real process kills, and are part
of the test suite.

## Resource limits

Every field of `Limits` is consulted by the code path named in its comment; a limit that
is not consulted does not exist. `Limits::describe()` enumerates all 28 so that the test
suite can prove the list is live: each field is driven to its boundary, its exact
structured rejection asserted, and a final test asserts that the driven set equals the
described set exactly.

```
max_policies                          max_candidates_per_policy
max_total_candidates                  max_evidence_sources
max_evidence_samples_per_series       max_evidence_requirements_per_policy
max_thresholds_per_policy             max_objective_terms
max_history_per_policy                max_decision_history
max_simultaneous_evaluations          max_pending_transitions
max_frame_bytes                       max_batch_size
max_publishers                        max_sessions
max_explanation_entries               max_persistence_record_bytes
max_store_bytes                       max_attempts
max_revocations                       max_snapshot_history
max_scope_routes                      max_scope_multipath_sets
max_adaptations_per_window            max_dampening_penalty
max_receive_stall_millis              max_policies_per_path
```

## Deterministic rejection precedence

When an input is defective in more than one way, it is rejected for one specific,
documented reason. `outcome_precedence()` exposes the order, and the adversarial suite
drives multi-defect inputs and asserts the exact winner.

| # | Stage | Outcomes |
| --- | --- | --- |
| 1 | wire integrity | WIRE_INTEGRITY, CORRUPT_STORE |
| 2 | frame decode | WIRE_MALFORMED |
| 3 | request decode and structural validation | MALFORMED_REQUEST, UNSUPPORTED_VERSION, INVALID_HYSTERESIS, INCOMPATIBLE_METRIC, ALREADY_EXISTS, NOT_FOUND |
| 4 | caller identity | UNAUTHORIZED |
| 5 | epoch | STALE_EPOCH |
| 6 | worker authority | STALE_WORKER, FENCED_WORKER |
| 7 | authority scope | UNAUTHORIZED_SCOPE |
| 8 | resource limits | RESOURCE_LIMIT, SESSION_LIMIT, EVALUATION_LIMIT |
| 9 | policy lifecycle | SUSPENDED, REVALIDATION_REQUIRED, REVOKED, RETIRED, POLICY_SUPERSEDED |
| 10 | expected generations | STALE_POLICY_GENERATION, STALE_EVIDENCE, STALE_ROUTE, STALE_MULTIPATH_SET, STALE_PATH_AUTHORITY |
| 11 | attempt id | ATTEMPT_CONFLICT |
| 12 | upstream currentness | WITHDRAWN_UPSTREAM |
| 13 | evidence currentness | INSUFFICIENT_EVIDENCE |
| 14 | candidate eligibility | NO_ELIGIBLE_CANDIDATE, NO_CURRENT_PREFERENCE |
| 15 | hold-down and cooldown | HOLD_DOWN_ACTIVE, COOLDOWN_ACTIVE |
| 16 | trigger evaluation | HYSTERESIS_NOT_CLEARED, NO_CHANGE, SUPPRESSED |
| 17 | churn limits | CHURN_LIMIT_REACHED |
| 18 | commit | GENERATION_OVERFLOW, DECISION_SUPERSEDED, ROLLBACK_REFUSED |

Within the authority stage the epoch outranks the lifecycle change it causes, so an
evaluation that spanned an epoch advance is told the epoch moved rather than that the
policy was suspended as a consequence.

## REAL, SYNTHETIC and UNSUPPORTED validation

**REAL** — actually executed and proven:

- real independent OS processes: a coordinator process and publisher processes;
- real forced process termination of a worker, and real coordinator restart against the
  same store, including repeated restart cycles;
- real loopback TCP transport, real sessions, real fencing on session loss;
- versioned persistence, corruption rejection and conservative recovery;
- upstream Path Authority, Multipath, Route and Weighted Path bindings through the
  documented notification contract;
- deterministic two-phase evaluation, watermark fencing and every mandatory race;
- an independent decision oracle re-deriving outcomes from raw inputs with no production
  helper.

**SYNTHETIC** — fabricated inputs, honestly labelled:

- telemetry streams: every sample in the test suite and the benchmarks is fabricated;
- the large path populations, policy populations, congestion scenarios, multi-site route
  adaptation and fabric-scale policy counts used by the scale exercise;
- the benchmark workloads.

**UNSUPPORTED** — not implemented, not tested, not claimed:

- physical switch programming of any kind;
- real line-rate traffic steering;
- physical packet-level convergence;
- vendor telemetry integration;
- multi-host control plane across more than one machine;
- consensus between coordinators, and split-brain prevention;
- cryptographic authentication of peers;
- global traffic engineering, bandwidth reservation, ECMP assignment, route installation,
  multipath membership change and weighted-policy commit.

Synthetic telemetry is never presented as a physical-network result.

## Build

Requirements: CMake 3.20 or newer, a C++20 compiler, and (on Windows) Winsock, which is
linked automatically.

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `ARF_BUILD_TESTS` | ON | build the test suites |
| `ARF_BUILD_TOOLS` | ON | build `arf`, `arf_coordinator`, `arf_publisher` |
| `ARF_BUILD_EXAMPLES` | ON | build the examples |
| `ARF_BUILD_BENCHMARKS` | ON | build the benchmarks |
| `ARF_WARNINGS_AS_ERRORS` | ON | `/WX` or `-Werror` |
| `ARF_ENABLE_ANALYZE` | OFF | MSVC `/analyze` |
| `ARF_ENABLE_ASAN` | OFF | AddressSanitizer where the toolchain supports it |

`ARF_ENABLE_ASAN=ON` requires the Visual Studio component **C++ AddressSanitizer**
(`Microsoft.VisualStudio.Component.VC.ASAN`) for the toolchain being used. When that
component is missing, the configure step fails with exactly that instruction instead of an
obscure linker error about `clang_rt.asan_dynamic_runtime_thunk`. On this release the
validated toolchain was the x64 Build Tools installation, which carries the component.

The library builds with `/W4 /WX /permissive-` on MSVC and `-Wall -Wextra -Wpedantic
-Werror` elsewhere, with zero first-party warnings. Exactly one warning is disabled
anywhere in the tree: a `#pragma warning(disable : 6101)` scoped to the two Windows SDK
headers `<winsock2.h>` and `<ws2tcpip.h>`, because that finding is inside code this
project does not own. Every first-party line is still compiled and analyzed at the full
level, and no first-party finding is suppressed.

## Test

```
ctest --test-dir build --output-on-failure
```

Four suites, run as plain commands with no timeouts and no sleeps:

| Suite | Contents |
| --- | --- |
| `arf_tests_core` | identities and generations, both lifecycle transition tables, metrics and aggregation, policy validation, evidence contracts |
| `arf_tests_state` | thresholds, hysteresis, hold-down, cooldown, dampening, churn, emergency, rollback, deterministic races, property tests over seeded schedules, the independent decision oracle |
| `arf_tests_io` | limits, persistence and corruption, wire codec, adversarial hardening |
| `arf_tests_distributed` | real worker death, real coordinator restart, repeated restarts, partial-frame defence |

Time-sensitive behaviour uses an injected deterministic clock that a test advances
explicitly. No test sleeps to make time pass, and no test depends on a timeout. Where an
internal wait is bounded — process readiness, the receive-stall bound — exceeding the bound
produces an explicit failed assertion rather than a silent pass.

Test binaries accept `--filter=<substring>` to run a subset.

## Install and find_package

```
cmake --install build --prefix <prefix>
```

```cmake
find_package(AdaptiveRoutingFabric CONFIG REQUIRED)
target_link_libraries(app PRIVATE SummonSoftwareLabs::AdaptiveRoutingFabric)
```

The package exports the imported target `SummonSoftwareLabs::AdaptiveRoutingFabric`,
the headers, and the package version. `AdaptiveRoutingFabricConfig.cmake` fails the
configure step with a fatal error if that target is missing, rather than letting a
downstream build succeed and fail later at link time. A standalone consumer project lives
in `tests/consumer` and is exercised by the closure validation: it configures, compiles,
links and runs against the installed tree only, with no source-tree leakage.

## Command line tools

```
arf_coordinator [--host H] [--port N] [--store PATH] [--ready-file PATH] [--max-sessions N]
arf_publisher   --endpoint HOST:PORT --publisher ID --boot ID --session ID
                [--script PATH] [--linger] [--output PATH]
arf             [--endpoint HOST:PORT] <command> [args]
```

The coordinator prints `LISTENING <host> <port>` as its first line and the optional
`RECOVERED ...` line after it, and runs until it is terminated. The publisher registers
one incarnation, prints `READY`, executes a script of `create-policy`, `declare`,
`evidence`, `evaluate`, `snapshot`, `revalidate`, `advance-epoch`, `fence` and
`say` commands, prints one line per command and then `DONE`. The CLI covers
`policy create|show|list|update|activate|suspend|resume`, `evidence publish`,
`evaluate`, `state show`, `explain`, `snapshot`, `diff`, `revalidate`, `revoke`,
`retire`, `store inspect`, `limits`, `version` and `help`. `store inspect` reads a
store file locally, with no coordinator, and reports the decode status and record counts.

All output is deterministic and script friendly: one `key=value` per line for state-like
output, the structured result rendering for mutations, exit code 0 for applied and for a
deterministic no-adaptation answer, 1 for a refusal or an unreachable coordinator, and 2 for
a usage error.

## Examples

Ten examples, each using the public umbrella header only, each driven by an injected
deterministic clock, each printing a short report and returning 0 on success:

| Example | Demonstrates |
| --- | --- |
| `example_latency_threshold` | an exact 20 % relative improvement committing A to B |
| `example_utilization_hysteresis` | a band threshold refusing departure below it and refusing an uncleared candidate |
| `example_hold_down_suppression` | a reverse adaptation suppressed, then released when the clock advances |
| `example_emergency_invalidation` | an emergency override abandoning an unauthorized path, and refusing to override legality |
| `example_stale_evidence` | a ticket taken before newer evidence being rejected as stale |
| `example_stale_path_authority` | a ticket taken before an authority advance being rejected |
| `example_worker_reincarnation` | a fresh incarnation fencing the old boot permanently |
| `example_coordinator_restart` | policies surviving a restart while authority and telemetry do not |
| `example_deterministic_tie_break` | canonical path order deciding a tie, with identical digests across engines |
| `example_rollback` | the rollback anchor being created by a transition and revalidated before use |

## Benchmarks

`arf_benchmarks` measures completed operations only, printing one line per benchmark with
the completed iteration count, the total nanoseconds and the nanoseconds per operation. It
covers policy registration, evidence ingestion, policy evaluation, suppression checks,
decision commit, path invalidation, snapshot construction, semantic digesting, persistence
save and load, a 10 000-policy population, a targeted evidence fan-out to 100 dependent
policies inside a 2 100-policy engine, and candidate evaluation at 4, 8, 16 and 32
candidates. Preparation is verified rather than assumed: a fixture that did not come up
reports zero completed iterations.

The fan-out row is the performance audit made visible: the cost of publishing evidence for
a path tracks the number of policies that depend on it through the reverse index, not the
size of the population.

Every number is a machine-specific observation, not a specification.

## Genuine limitations

- **No cryptographic authentication.** The wire integrity trailer is a deterministic,
  non-cryptographic hash. It detects corruption, not forgery. Peer trust is established by
  the coordinator's epoch, worker, scope and generation rules, not by a signature. There is
  no encryption on the transport.
- **No consensus and no split-brain prevention.** One coordinator owns authority. Two
  isolated coordinators over the same store are not reconciled by this runtime.
- **One route per policy.** Blast radius is bounded by construction. Wider change means more
  policies, and coordination downstream.
- **Upstream bindings are a contract, not a live integration.** Path Authority, Multipath,
  Route and Weighted Path facts arrive as explicit notifications carrying their exact
  generations, and the validation drives a conforming upstream through that contract. The
  library links against none of those runtimes.
- **Weight proposals are intent only.** A proposal names a target set, the weight generation
  it was computed against and the proposed weights. Nothing in this runtime commits it.
- **No ECMP participation at all.** Equal-cost assignment is not read, proposed or mutated.
- **Convergence stops here.** A committed decision is desired preference. Whether traffic
  moved, and how the fabric converges, is not observed or claimed.
- **Recovery is conservative to the point of inconvenience.** After a restart no evidence is
  current, every non-terminal policy needs revalidation and the epoch has advanced. That is
  deliberate.
- **The rollback anchor is the displaced preference.** A rollback walks back one
  revalidated step at a time; there is no branching history and no multi-step undo.
- **Bounded by configured limits, by design.** A deployment that needs more policies,
  candidates, evidence series or retained history raises the limit explicitly rather than
  discovering an unbounded allocation.
- **Scale numbers are synthetic.** The large populations and fan-outs in the benchmarks are
  generated, not observed on a real fabric.
- **Windows is the validated platform.** The transport is written portably, but the
  distributed proofs, the sanitizer diagnosis and the static analysis in this release were
  executed on Windows with MSVC; other platforms are untested here.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
