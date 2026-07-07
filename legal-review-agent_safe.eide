#! Legal-review agent — untrusted a contract clause can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires flagClause — the legal-review agent sink
#! @effect io
#! @confidence 70
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant flagClause confidence 70

type ClauseRisk = LowRisk | MediumRisk | HighRisk
type Decision = FlagClause(ClauseRisk) | ApproveClause

let raw = fetch<web>  # UNTRUSTED a contract clause — tainted
quarantined { let d = extract<Decision>(raw) confidence 70 }  # only a fixed Decision (payloads too) crosses
privileged { flagClause(d) }  # act on the trusted decision only
