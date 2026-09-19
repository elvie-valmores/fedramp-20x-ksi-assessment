"""Mechanisms whose dependencies haven't been built yet, per
docs/PROJECT-CONTEXT.md's build order. Each is still registered and
raises loudly with the reason when a check definition is routed to it,
rather than being silently omitted -- same convention
inventory/gcp_source.py used for GCP before that existed.
"""

from __future__ import annotations

from base import CheckDefinition, CheckResult, Mechanism


class _NotYetBuilt(Mechanism):
    depends_on: str = ""

    def run(self, check: CheckDefinition) -> CheckResult:
        raise NotImplementedError(
            f"{self.name} is not implemented yet -- depends on {self.depends_on} "
            "(see docs/PROJECT-CONTEXT.md build order)."
        )


class LogQuery(_NotYetBuilt):
    name = "log_query"
    depends_on = "the normalized log corpus and query layer (build order step 4)"


class DeclaredVersusLiveComparison(_NotYetBuilt):
    name = "declared_versus_live_comparison"
    depends_on = "a Terraform-state reader paired against live queries -- not wired up yet"


class RegisterRead(_NotYetBuilt):
    name = "register_read"
    depends_on = "the consolidated resource register (not yet built)"


class PipelineConfigRead(_NotYetBuilt):
    name = "pipeline_config_read"
    depends_on = "a CI/CD pipeline, which doesn't exist in this repo yet"


class DeliberateTest(_NotYetBuilt):
    name = "deliberate_test"
    depends_on = "the deliberate test harness (build order step 8)"


class RecordStore(_NotYetBuilt):
    name = "record_store"
    depends_on = "a chosen record-store target -- not yet decided"


class EffectiveAccessAnalysis(_NotYetBuilt):
    name = "effective_access_analysis"
    depends_on = "IAM/access modeling (build order steps 5-6 territory)"
