# Shared helpers for the authored rules (KSI-MLA-EVC). Every rule reads the
# Terraform plan rendered to JSON, never the source: a value resolved at
# plan time -- a variable, a data source, a computed reference -- is only
# visible there (DECISIONS.md, 2026-09-14).
package fedramp.policy

import rego.v1

# What will exist after the apply: created, updated or unchanged.
resources contains r if {
	some r in input.resource_changes
	r.mode == "managed"
	not "delete" in r.change.actions
}

of_type(t) := {r | some r in resources; r.type == t}

# The configuration address: the plan address without its count or
# for_each index, which is how configuration references name it.
config_address(r) := regex.replace(r.address, `\[[^\]]*\]$`, "")

config_resources contains c if some c in input.configuration.root_module.resources

# Configuration resources of type t whose attribute attr references the
# resource at config address target. Used to find a bucket's companion
# resources, which name the bucket by reference.
referencing(t, attr, target) := {c |
	some c in config_resources
	c.type == t
	target in c.expressions[attr].references
}

# An after-value Terraform cannot know until apply.
unknown(r, attr) if r.change.after_unknown[attr] == true

# ISO 8601 durations of hours and minutes (PT4H, PT1H30M) in seconds.
duration_seconds(d) := s if {
	m := regex.find_all_string_submatch_n(`^PT(?:(\d+)H)?(?:(\d+)M)?$`, d, 1)[0]
	s := (to_number_or_zero(m[1]) * 3600) + (to_number_or_zero(m[2]) * 60)
}

to_number_or_zero(x) := 0 if x == ""

to_number_or_zero(x) := to_number(x) if x != ""

violation(rule, r, msg) := {"rule": rule, "address": r.address, "msg": msg}
