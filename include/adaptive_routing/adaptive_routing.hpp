// Adaptive Routing Fabric 1.0.0 public umbrella header.
//
// Adaptive Routing Fabric is the evidence-driven path-selection adaptation and
// controlled transition runtime of the Distributed Fabric Infrastructure /
// Fabric OS stack. It owns adaptation-policy identity and generations,
// evidence-bound adaptation decisions, explicit thresholds, hysteresis,
// hold-down, cooldown, bounded dampening, candidate eligibility, deterministic
// ranking, stale-decision fencing, rollback intent, snapshots, diffs,
// explanations and versioned persistence.
//
// It does not compute candidate paths, decide path legality, own route
// lifecycle, own multipath membership, own ECMP assignment, own explicit path
// weighting, sequence network-wide convergence or solve global traffic
// engineering.
#ifndef ADAPTIVE_ROUTING_ADAPTIVE_ROUTING_HPP
#define ADAPTIVE_ROUTING_ADAPTIVE_ROUTING_HPP

#include "adaptive_routing/authority.hpp"
#include "adaptive_routing/clock.hpp"
#include "adaptive_routing/codec.hpp"
#include "adaptive_routing/decision.hpp"
#include "adaptive_routing/evidence.hpp"
#include "adaptive_routing/fabric.hpp"
#include "adaptive_routing/ids.hpp"
#include "adaptive_routing/limits.hpp"
#include "adaptive_routing/lifecycle.hpp"
#include "adaptive_routing/metrics.hpp"
#include "adaptive_routing/outcome.hpp"
#include "adaptive_routing/persistence.hpp"
#include "adaptive_routing/policy.hpp"
#include "adaptive_routing/transport.hpp"
#include "adaptive_routing/upstream.hpp"
#include "adaptive_routing/version.hpp"
#include "adaptive_routing/view.hpp"
#include "adaptive_routing/wire.hpp"

#endif  // ADAPTIVE_ROUTING_ADAPTIVE_ROUTING_HPP
