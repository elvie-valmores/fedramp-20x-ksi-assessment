"""Mechanism: assert something about how the delivery pipeline is configured.

Used for evidence about the build path rather than about running
infrastructure -- that actions are pinned, that no static credential is
referenced, that scanning happens before publishing rather than after.

This reads the workflow files in the repository, which is deliberate.
The pipeline's configuration *is* the committed file: GitHub runs what is
on the default branch, so the file under assessment and the file on disk
are the same artifact. Nothing here calls the GitHub API, so these checks
run with no network and no credentials, and keep working when the
environment is torn down.

Check params:
    workflow   filename under .github/workflows/, e.g. "build-and-push.yml"
    assertion  which handler below to run
    ...        plus whatever that handler needs

One handler per assertion for the same reason cloud_api_config_read has
one per resource: "is it configured correctly" means something different
for each, and a single generic matcher would express the question less
clearly than the question deserves.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from base import CheckDefinition, CheckResult, Mechanism

WORKFLOWS_DIR = Path(__file__).resolve().parents[2] / ".github" / "workflows"

# A 40-character hex string. Tags and branch names are mutable pointers;
# only a commit SHA names an immutable tree.
SHA_PINNED = re.compile(r"^[^@]+@[0-9a-f]{40}$")

# Secret names that would indicate a long-lived cloud credential. The
# federated path uses no secrets at all, so any of these appearing is the
# thing KSI-IAM-SNU's durability hierarchy rates as failing.
STATIC_CREDENTIAL_HINTS = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GCP_SA_KEY",
    "GOOGLE_CREDENTIALS",
    "GOOGLE_APPLICATION_CREDENTIALS_JSON",
)


class PipelineConfigRead(Mechanism):
    name = "pipeline_config_read"

    def run(self, check: CheckDefinition) -> CheckResult:
        assertion = check.params["assertion"]
        handler = getattr(self, f"_{assertion}", None)

        if handler is None:
            raise NotImplementedError(
                f"pipeline_config_read has no handler for assertion={assertion!r} "
                f"yet -- add one as new checks need it."
            )

        path = WORKFLOWS_DIR / check.params["workflow"]
        if not path.exists():
            return CheckResult(
                check.id,
                False,
                {"path": str(path)},
                f"workflow {check.params['workflow']} does not exist",
            )

        return handler(check, path.read_text())

    # --- assertions ---

    def _actions_pinned_to_sha(self, check: CheckDefinition, source: str) -> CheckResult:
        """Passes if every `uses:` names a commit SHA.

        KSI-CNA-DFP build row: pin to a commit, not a tag. A tag is a
        mutable pointer, and pinning to one means trusting whoever can
        move it -- which for a third-party action is not the repository
        owner.

        Read from the raw text rather than the parsed tree on purpose. A
        `uses:` inside a job this parser mishandles would be missed by a
        structural walk and is caught here, and there is no version of
        this check where scanning less is safer.
        """
        uses = re.findall(r"^\s*-?\s*uses:\s*(\S+)", source, re.M)
        unpinned = [u for u in uses if not SHA_PINNED.match(u)]

        # Local actions (./path) are part of this repository and carry no
        # third-party trust, so they are not expected to be pinned.
        unpinned = [u for u in unpinned if not u.startswith("./")]

        return CheckResult(
            check.id,
            not unpinned,
            {"total": len(uses), "unpinned": unpinned},
            f"all {len(uses)} action(s) pinned to a commit SHA"
            if not unpinned
            else f"{len(unpinned)} action(s) not pinned: {', '.join(unpinned)}",
        )

    def _no_static_cloud_credentials(
        self, check: CheckDefinition, source: str
    ) -> CheckResult:
        """Passes if the workflow references no long-lived cloud credential.

        KSI-IAM-SNU ranks credentials by durability: no credential, then a
        short-lived federated exchange, then static keys as failing. The
        pipeline federates, so the correct count of static credential
        references is zero and any occurrence is a regression rather than
        a judgement call.
        """
        found = [name for name in STATIC_CREDENTIAL_HINTS if name in source]

        return CheckResult(
            check.id,
            not found,
            {"matched": found, "searched_for": list(STATIC_CREDENTIAL_HINTS)},
            "no static cloud credential referenced"
            if not found
            else f"static credential reference(s) found: {', '.join(found)}",
        )

    def _permissions_declared(self, check: CheckDefinition, source: str) -> CheckResult:
        """Passes if the workflow declares `permissions` and does not grant write-all.

        An absent block means the repository default applies, which is
        broader than anything here needs and changes without the workflow
        changing. Declaring it is what makes the grant reviewable.
        """
        workflow = self._parse(source)
        permissions = workflow.get("permissions")

        if permissions is None:
            return CheckResult(
                check.id,
                False,
                {"permissions": None},
                "no workflow-level permissions block; repository default applies",
            )

        # `permissions: write-all` is a scalar, not a mapping, and grants
        # everything -- declared, but not least privilege.
        if permissions == "write-all":
            return CheckResult(
                check.id, False, {"permissions": permissions}, "permissions: write-all"
            )

        return CheckResult(
            check.id,
            True,
            {"permissions": permissions},
            f"permissions declared: {permissions}",
        )

    def _step_present(self, check: CheckDefinition, source: str) -> CheckResult:
        """Passes if the named job contains a step whose name matches.

        Requires params: job, step (a substring, matched case-insensitively).

        Used where a determination rests on a stage existing at all --
        signing, signature verification, dependency scanning.
        """
        job = check.params["job"]
        wanted = check.params["step"].lower()
        names = self._step_names(self._parse(source), job)

        found = [n for n in names if wanted in n.lower()]
        return CheckResult(
            check.id,
            bool(found),
            {"job": job, "steps": names, "matched": found},
            f"job {job!r} has step matching {check.params['step']!r}"
            if found
            else f"job {job!r} has no step matching {check.params['step']!r}",
        )

    def _step_precedes(self, check: CheckDefinition, source: str) -> CheckResult:
        """Passes if one step appears before another in the same job.

        Requires params: job, before, after (substrings, case-insensitive).

        Order is load-bearing in a build pipeline in a way that presence
        alone is not. Scanning after publishing still scans, but it
        reports on an artifact that has already been pushed; verifying a
        signature after deploying verifies something already running.
        Both would satisfy a presence check and neither is the control.
        """
        job = check.params["job"]
        before = check.params["before"].lower()
        after = check.params["after"].lower()
        names = self._step_names(self._parse(source), job)

        lowered = [n.lower() for n in names]
        before_at = next((i for i, n in enumerate(lowered) if before in n), None)
        after_at = next((i for i, n in enumerate(lowered) if after in n), None)

        if before_at is None or after_at is None:
            missing = check.params["before"] if before_at is None else check.params["after"]
            return CheckResult(
                check.id,
                False,
                {"job": job, "steps": names},
                f"step matching {missing!r} not found in job {job!r}",
            )

        ordered = before_at < after_at
        return CheckResult(
            check.id,
            ordered,
            {"job": job, "before_index": before_at, "after_index": after_at, "steps": names},
            f"{names[before_at]!r} precedes {names[after_at]!r}"
            if ordered
            else f"{names[before_at]!r} does NOT precede {names[after_at]!r}",
        )

    def _triggers_limited_to(self, check: CheckDefinition, source: str) -> CheckResult:
        """Passes if push triggers are confined to the listed branches.

        Requires param: branches (a list).

        The OIDC trust policies pin the subject to one ref. A workflow
        that can be triggered from another branch would mint tokens that
        the trust policy then rejects, which reads as a broken pipeline
        rather than as the boundary working -- so the two are kept in
        agreement here.
        """
        expected = set(check.params["branches"])
        triggers = self._parse(source).get("on", {})

        push = triggers.get("push") if isinstance(triggers, dict) else None
        actual = set((push or {}).get("branches", [])) if isinstance(push, dict) else set()

        # No push trigger at all is narrower than any allowlist, not a gap.
        if push is None:
            return CheckResult(
                check.id, True, {"push": None}, "workflow has no push trigger"
            )

        extra = actual - expected
        return CheckResult(
            check.id,
            not extra,
            {"expected": sorted(expected), "actual": sorted(actual)},
            f"push limited to {sorted(actual)}"
            if not extra
            else f"push also allowed from {sorted(extra)}",
        )

    # --- helpers ---

    @staticmethod
    def _parse(source: str) -> dict[str, Any]:
        """Parse a workflow, working around YAML's treatment of `on`.

        In YAML 1.1, which PyYAML implements, the bare word `on` is a
        boolean. So a workflow's `on:` key parses as True rather than as
        the string "on", and every naive lookup of workflow["on"] misses
        it. Normalising here means no handler has to know that.
        """
        workflow = yaml.safe_load(source) or {}
        if True in workflow and "on" not in workflow:
            workflow["on"] = workflow.pop(True)
        return workflow

    @staticmethod
    def _step_names(workflow: dict[str, Any], job: str) -> list[str]:
        """Names of the steps in one job, in order, unnamed steps included."""
        jobs = workflow.get("jobs") or {}
        if job not in jobs:
            return []
        steps = jobs[job].get("steps") or []
        return [s.get("name") or s.get("uses") or "<unnamed>" for s in steps]
