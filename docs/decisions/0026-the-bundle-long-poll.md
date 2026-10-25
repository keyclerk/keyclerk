# 0026. An edge may wait for its next bundle

- Status: accepted (2026-10-25), built in 0.25.0. Edge protocol 1.2 (two optional query parameters on the bundle
  pull; edge protocol 1.1 edges are unaffected).
- Context: an edge learns of a change at its next pull, 60 seconds by default with jitter. A revocation or a narrowed
  lease, for example when a trust signal lowers a band, therefore takes up to a minute to reach the edge. Nothing ever
  dials an edge (it calls out, never in), so a separate notice would arrive on the same pull and gain nothing. The gain
  comes from delivery: the edge keeps its pull open, and the desk answers it as soon as there is something new. An edge
  implementation asked for this.

## Decision
1. **Two query parameters on the pull.** `GET /api/v1/edge/bundle?after=<serial>&wait=<seconds>`: `after` is the serial
   of the newest bundle the edge accepted; `wait` is how long the edge will wait, in whole seconds from 1. The request
   signature already covers the path with its query (section 3), so both are signed, and the nonce is accepted once:
   a replayed long-poll is refused like any replayed request. No new signed format, and no change to the bundle or to
   its verification.
2. **What it waits for is content, not a serial.** The desk issues a new serial on every bundle, so "a higher serial"
   would answer every time. It answers when this edge's bundle says something other than the bundle with serial
   `after` said: its leases, visit leases, revocations, ceiling, policy references or governed roles. Serial, issue
   time, format and key id are not compared. The desk keeps a digest of each of an edge's recent bundles to compare
   with (`keyclerk.edge.bundle_digest`).
3. **Always a fresh bundle.** The answer, changed or timed out, is a newly issued bundle. A timed-out wait therefore
   renews the edge's offline horizon exactly as a pull does, and the edge needs no second kind of request.
4. **Answered at once** when the content already differs, when `after` is a serial the desk does not know (another
   desk, or older than the digests it keeps), and when the desk already holds its cap of open waits. Over the cap the
   edge simply gets a plain pull: degraded, never an error.
5. **Bounds.** A wait above 55 seconds is held to 55 (under common proxy idle timeouts), never refused. An edge holds
   at most as many open waits as it has nodes (one, or two for a high-availability edge): a new wait answers the
   oldest at once, so reconnects never pile up. `serial` (the lost-answer fetch) together with `wait` is refused,
   since they ask for different things; a malformed `wait` is refused. The cap of open waits per desk is
   configuration (`edge.long_poll_max`, default 256).
6. **What wakes a wait.** Every committed change to the records and every new ceiling wakes the waits; each rebuilds
   its edge's bundle and answers only if the content changed. Time alone wakes nothing: an edge ends a lease at its own
   `until`.
7. **Without `wait`, nothing changes.** A pull without it is today's pull. An edge talking to an older desk gets an
   immediate answer, which is a plain pull: its fallback is automatic. An edge keeps its jittered pull interval as the
   floor after any immediate answer, and never loops tight.

## Consequences
- A revocation reaches a connected edge in about a second instead of up to a minute.
- Each connected edge keeps one request open at the desk: a sleeping thread, and a longer-lived connection at the
  proxy. The cap bounds both.
- The wake-up is inside one desk process. A desk run as several processes needs a shared notification (for example
  the store's own change feed) before the long-poll works across them; until then each process wakes only for the
  changes it committed, and a wait on another process answers at its timeout. Written here as the known limit.
- When an edge's answer arrives tells an observer of the connection when its content changed. The content stays
  encrypted and signed; the timing is the residual.
- Proven by `tests/test_edge_long_poll.py` (a change answers at once, a wake that changes nothing keeps waiting, a
  timed-out wait renews, an unknown serial, a second wait answers the first, the cap, the maximum, malformed waits, a
  replay) and by the `requests` family of the conformance set (the exact bytes an edge signs, the query signed as sent,
  tampering refused).
