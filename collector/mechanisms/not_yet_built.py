"""The six mechanisms that have no implementation yet.

Each one waits on infrastructure or tooling that does not exist in this
repo yet. They are registered anyway so that routing a check to one
produces a clear explanation of what is missing, instead of the
mechanism simply not being found.

Running a check against one of these is reported as a skip, not a
failure -- nothing is broken, it just hasn't been built.
"""

from __future__ import annotations

from base import CheckDefinition, CheckResult, Mechanism


class _NotYetBuilt(Mechanism):
    """Base class that raises with whatever the subclass is waiting on."""

    depends_on: str = ""

    def run(self, check: CheckDefinition) -> CheckResult:
        raise NotImplementedError(
            f"{self.name} is not implemented yet -- depends on {self.depends_on}."
        )


class DeclaredVersusLiveComparison(_NotYetBuilt):
    """Would compare Terraform's declared state against what's running."""

    name = "declared_versus_live_comparison"
    depends_on = "a reader for Terraform state, to diff against live queries"


class RegisterRead(_NotYetBuilt):
    """Would read values from the project's register of tracked decisions."""

    name = "register_read"
    depends_on = "the consolidated resource register"


class PipelineConfigRead(_NotYetBuilt):
    """Would inspect CI/CD pipeline configuration."""

    name = "pipeline_config_read"
    depends_on = "a CI/CD pipeline, which this repo does not have yet"


class DeliberateTest(_NotYetBuilt):
    """Would break something on purpose and confirm the control catches it."""

    name = "deliberate_test"
    depends_on = "the deliberate test harness"


class RecordStore(_NotYetBuilt):
    """Would confirm a required record exists with the right fields."""

    name = "record_store"
    depends_on = "a chosen record store, not yet selected"


class EffectiveAccessAnalysis(_NotYetBuilt):
    """Would compute who can actually reach what, beyond what's declared."""

    name = "effective_access_analysis"
    depends_on = "the IAM and access model, not yet built"
