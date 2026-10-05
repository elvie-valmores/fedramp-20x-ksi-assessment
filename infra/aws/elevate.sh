#!/usr/bin/env bash
# Just-in-time elevation (elevation.tf).
#
#   elevate.sh start "<justification>" [minutes]   request ElevatedAdmin (default 60, 15 to 240)
#   elevate.sh status                              the running elevation, if any
#   elevate.sh release                             end it early
#
# Runs as the standing read-only profile. Once the grant is confirmed, use
# the elevated profile: `aws ... --profile caliper-elevated`, or
# `AWS_PROFILE=caliper-elevated terraform apply ...`. A new grant can take a
# minute to reach the sign-in; run `aws sso login --profile caliper-elevated`
# if the profile says the role is not assigned.
#
# Release stops the workflow; the backstop removes the assignment within 15
# minutes. Either way, a session already open lasts at most its hour.

set -euo pipefail

PROFILE="${ELEVATE_PROFILE:-caliper-readonly}"
REGION=us-east-1
ACCOUNT=437672023758
MACHINE="arn:aws:states:${REGION}:${ACCOUNT}:stateMachine:fedramp-20x-ksi-elevation"

aws_() { aws --profile "$PROFILE" --region "$REGION" "$@"; }

running() {
  aws_ stepfunctions list-executions --state-machine-arn "$MACHINE" --status-filter RUNNING \
    --query 'executions[0].executionArn' --output text
}

case "${1:-}" in
  start)
    justification="${2:?usage: elevate.sh start \"<justification>\" [minutes]}"
    minutes="${3:-60}"
    [[ "$minutes" =~ ^[0-9]+$ ]] || { echo "minutes must be a whole number" >&2; exit 2; }
    [[ "$(running)" == "None" ]] || { echo "an elevation is already running: $(running)" >&2; exit 1; }
    caller=$(aws_ sts get-caller-identity --query Arn --output text)
    input=$(python3 -c 'import json,sys; print(json.dumps({"justification": sys.argv[1], "minutes": int(sys.argv[2]), "requested_by": sys.argv[3]}))' \
      "$justification" "$minutes" "$caller")
    execution=$(aws_ stepfunctions start-execution --state-machine-arn "$MACHINE" \
      --name "elevate-$(date -u +%Y%m%dT%H%M%SZ)" --input "$input" --query executionArn --output text)
    echo "started: $execution"
    # Wait for the grant to be confirmed, or for a refusal.
    for _ in $(seq 1 40); do
      status=$(aws_ stepfunctions describe-execution --execution-arn "$execution" --query status --output text)
      if [[ "$status" != "RUNNING" ]]; then
        echo "elevation ended: $status"
        aws_ stepfunctions describe-execution --execution-arn "$execution" --query '[error,cause]' --output text
        exit 1
      fi
      # --max-results asks the API for one event. --max-items would page in
      # the CLI and print a NextToken line after the type, which never
      # matches (found on the first test, 2026-10-03).
      state=$(aws_ stepfunctions get-execution-history --execution-arn "$execution" --reverse-order \
        --max-results 1 --no-paginate --query 'events[0].type' --output text)
      if [[ "$state" == "WaitStateEntered" ]]; then
        echo "granted for ${minutes} minutes. Use --profile caliper-elevated."
        exit 0
      fi
      sleep 3
    done
    echo "still granting after two minutes; check: elevate.sh status" >&2
    exit 1
    ;;
  status)
    execution=$(running)
    if [[ "$execution" == "None" ]]; then echo "no elevation running"; exit 0; fi
    aws_ stepfunctions describe-execution --execution-arn "$execution" \
      --query '{execution: executionArn, started: startDate, input: input}' --output json
    ;;
  release)
    execution=$(running)
    if [[ "$execution" == "None" ]]; then echo "no elevation running"; exit 0; fi
    aws_ stepfunctions stop-execution --execution-arn "$execution" --cause "released by the operator" >/dev/null
    echo "released: $execution. The backstop removes the assignment within 15 minutes."
    ;;
  *)
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
