#! VULNERABLE legal-review-agent — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant flagClause confidence 70

let raw = fetch<web>
privileged { flagClause(raw) }  # tainted -> tool: REJECTED
