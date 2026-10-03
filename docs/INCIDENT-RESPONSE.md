# Incident response

The manual response procedure, written 2026-10-03 when the automated responder (KSI-IAM-SUS) was
descoped. Detection and alerting stay automated. Everything after the alert is a person following
this page.

It is the response plan KSI-INR-RIR's control positions point at (`registers/control-positions.yaml`).
It covers the incident classes the detection path raises. It is not a complete incident response
program, and it does not pretend to be one.

## What raises an alert

Each alert is an email to the detection topic's subscriber.

| Alert | Source | Typical meaning |
|---|---|---|
| Failed authentication detected | The daily detection query over the normalized corpus | Repeated failed sign-ins: a guessing attempt, or a misconfigured client |
| GuardDuty finding | GuardDuty, through EventBridge | Threat activity: unusual API use, credential exfiltration patterns, malicious IPs, RDS login anomalies, S3 or Lambda anomalies |
| Evidence key disable or delete attempt | The evidence key's EventBridge rule | Someone tried to destroy or disable the key protecting the audit store |
| Normalizer errors | CloudWatch alarm | The log pipeline is failing, so later detections may be blind |
| Log store growth | CloudWatch alarm | Unexpected volume: a runaway source, or a flood |

## 1. Triage, within the hour

1. **Read the alert,** and note the principal, the time and the resource.
2. **Find the activity** in the corpus. Athena, workgroup `fedramp-20x-ksi-log-corpus`:
   ```sql
   SELECT from_unixtime(time/1000), actor.user.name, api.service.name, api.operation, status, src_endpoint.ip
   FROM normalized_events
   WHERE source='aws' AND dt >= date_format(date_add('day', -1, current_date), '%Y-%m-%d')
     AND actor.user.name LIKE '%<principal>%'
   ORDER BY time
   ```
3. **Decide whether it is an incident:** an unexplained action by any principal, any root activity
   you did not do, or any evidence-key event. If you can explain it, record why (step 5) and stop.

## 2. Contain

Use the narrowest action that stops the activity.

**A role's sessions are being misused.** Revoke every session issued before now. New sessions, once
the cause is fixed, still work.
```
aws iam put-role-policy --role-name <role> --policy-name revoke-older-sessions --policy-document '{
  "Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
  "Condition":{"DateLessThan":{"aws:TokenIssueTime":"<now, ISO 8601 UTC>"}}}]}'
```
This is an in-place change of the emergency kind. Record it in `registers/change-exceptions.yaml`
under `emergency_response`.

**The operator's own sign-in is suspect.** Sign out of Google everywhere, rotate the Google password,
and revoke the Identity Center session from the console (IAM Identity Center, Users, the user, Active
sessions). Root, with its hardware key, is the break-glass path.

**A workload is misbehaving.** Stop it.
```
aws ecs update-service --cluster fedramp-20x-ksi --service <api|worker> --desired-count 0
gcloud scheduler jobs pause analytics-pipeline --location us-central1 --project fedramp-20x-ksi-assessment
```

**The whole application environment is suspect.** Tear it down with `infra/aws/teardown.sh`. The
evidence, the images and the keys persist by design.

**A key is under attack.** Only root can disable or delete the persistent keys. Confirm the attempt
failed: the alert means it was denied. Then find the principal and contain it as above.

## 3. Recover

Redeploy from version control, never by hand (KSI-CMT-RMV):

- **Declared state:** `terraform apply` per root. Drift is what tells you what changed.
- **The database:** point-in-time restore, `infra/aws/restore_database.sh`.
- **The pipeline's data:** re-run the job. It re-reads every extract within 30 days.

## 4. Reconcile

Every emergency change is folded back into declared state, or reverted, the same day:

- **Remove the revocation policy** once the cause is fixed.
- **Confirm drift is clean in both clouds** (`svc-acm-ops-aws-no-drift` and `svc-acm-ops-gcp-no-drift`).

## 5. Record

Add an entry to `docs/DECISIONS.md` with:

- what alerted, and when
- what was found
- what was done, and when
- what changed afterwards

A false positive is recorded too, with why it was one. A detection nobody looked at is not evidence
that nothing happened.

## What this does not cover

These positions are in `registers/control-positions.yaml`:

- **Reporting to FedRAMP or agencies:** this persona has neither.
- **Assisting users:** there are none.
- **Breach notification:** no personal data is held.
