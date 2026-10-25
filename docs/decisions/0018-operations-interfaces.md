# 0018. Operations interfaces: health, metrics, audit export, SOAR, identity visibility

- Status: accepted (2026-10-24, choices H1 to H6). H1 to H3 built for 0.24.0 (keyclerk/health.py, keyclerk/metrics.py); H4 to H6 not built.
- Context: KeyClerk has an event log (CloudEvents 1.0 envelopes holding OCSF events, pseudonymous, read by a cursor)
  and identity visibility designed in 0009 section 6, but no health or metrics endpoint, no forwarder to a SIEM, no
  SOAR path and no feed for other platforms. The runtime stays compact, flexible, federable and distributable,
  self-healing and reconcilable, and fully auditable; every outbound path is off by default.

## Decision
1. **Health (H1).** `/healthz` (the process serves) and `/readyz` (status only): ready means the store opens and its
   head verifies, the policy modules are loaded, the signer answers, the last reconcile is within its bound, and no
   restore is in progress (0019). Never downstream systems: a broker that is down is a metric and an alert. The detail
   is on the management listener, for an operator. The signer and the reconciler have their own liveness.
2. **Metrics (H2).** Prometheus text (OpenMetrics) on a separate management listener with its own token, standard
   library only. A short fixed list, each metric tied to an alert or a budget: changes and refusals by reason class,
   pending approvals, check duration (0017's budget), reconcile lag and drift, edge pulls, silences and attestation
   failures, signer latency, backup age (0019). Push stacks use an OpenTelemetry Collector the deployment runs, which
   scrapes the page; in-process OTLP was estimated at 8 to 12 MB of image and 10 to 20 MB resident per process.
3. **Labels (H3).** Pseudonymous ids are allowed as labels, for per-person drill-down. To settle at build time: a
   pseudonym key per sink (so a metrics store cannot be joined with the audit trail) and such labels only where needed.
   Settled at build time (0.24.0): no metric needs one, so none carries a person, group or edge id; labels come from
   fixed value lists (anything else counts as `other`), and per-person drill-down stays in the audit trail.
4. **Audit to a SIEM (H4).** Both: a pull API over the event cursor (the default; an authenticated reader), and syslog
   over TLS (RFC 5424 over RFC 5425), off by default, with a CA pin, resuming from the cursor, which advances only after
   a write and flush. One format: OCSF JSON. JSON logs on stdout for container collectors. Every event carries its
   records revision and hash-chain position, so a SIEM's copy can be checked against the signed history.
5. **SOAR (H5).** Outbound signed webhooks for chosen event types, from the cursor, off by default. Inbound, a SOAR is a
   workload persona (0011) that may only propose protective changes (suspend a person, end a lease, raise a situation
   level), never a grant; policy decides whether one applies at once. A rate ceiling per hour, past it a person decides
   and an incident is raised; people in active break-glass or on call are spared unless a person confirms; effects at
   the broker only through the reconciler; lifting a suspension still takes two people.
6. **Identity visibility and other platforms (H6).** Both now: a read API of effective access built on the 0017
   timeline, plus the OCSF events, pseudonymous by default, real identifiers only for a named consumer and purpose
   (policy, logged at each read), one documented read model; and Shared Signals (OpenID SSF with CAEP), starting with
   "access ended" so receivers end sessions. Streams are off by default and receivers configured with their trust.

## Consequences
A deployment can run KeyClerk under any monitoring stack and SOC without KeyClerk sending anything it was not told
to. The SOAR gets fast containment that is signed like every other change. The read API depends on 0017.
