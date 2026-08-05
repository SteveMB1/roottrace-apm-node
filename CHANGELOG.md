# Changelog

## 0.4.3 (2026-07-31)

- **Security sinks.** Every `child_process` entry point (`spawn`, `exec`,
  `execFile`, and their sync forms) now reports that a process was spawned to
  `POST /apm/security-events`. Because it fires inside a transaction the report
  carries the request that caused it: trace id, endpoint, and method, with the
  client address resolved server-side from the connection rather than trusted
  from the reporting process.
  - **The fact, never the payload.** The executable is recorded; the arguments
    are not, because an attacker's argv *is* the exfiltration.
  - Buffer capped at 100 events between flushes and dropped rather than
    retried: a process being driven by an attacker outruns any flush interval,
    and an unbounded queue inside the victim is its own denial of service.
  - Off with `securitySinks: false` on `init()`.

## 0.4.2 (2026-07-30)

- **Fixed: `upload_interval_seconds` did nothing.** The server sends it, the
  RootTrace UI offers it as a control between 15 and 900 seconds, and this SDK
  clamped it on arrival and then never read it — profiles were drained on the
  metric flush cadence instead. That is 30 seconds by default and can be set to
  5 via `intervalSeconds`, so a service could upload twelve slivers where the
  configured window asked for one profile. The Go and Java SDKs already gated
  on this; Node and Python did not. Uploads now happen once per configured
  interval, measured on `performance.now()` like the config poll and timed from
  when the profiler started so the first one covers a whole window.
  Flamegraphs were never wrong — the server merges everything into five-minute
  buckets regardless — but the setting was a lie and the upload count was
  several times what was asked for.

## 0.4.1 (2026-07-30)

- **The profiling config poll now uses a monotonic clock, and treats "never
  fetched" as due.** Two hazards, one of which the Python SDK shipped as a real
  bug: `performance.now()` starts near zero at process start, so an initial `0`
  on the interval guard would skip the very first fetch for a minute; and
  `Date.now()` is wall clock, so a backwards NTP step — routine on a VM that
  boots with a bad clock and then syncs — would stall polling until wall time
  caught up. Node was correct on the first count by accident and exposed on the
  second; it is now explicit about both.
- Toolchain pinned exactly (`eslint`, `mongodb`) rather than carried on a caret
  range. An unpinned linter turns any upstream release into a red build on code
  nobody touched, which is what happened to the Python SDK's CI.

## 0.4.0 (2026-07-30)

- **Continuous profiling**, off until enabled from the RootTrace UI. The SDK
  polls `GET /api/apm/config` on the background flush loop and starts nothing
  on its own, so the switch is reachable during the incident it is causing
  rather than needing a redeploy. The poll is deliberately not part of
  `flush()`: a caller asking to flush wants its buffered metrics sent, not a
  second connection opened to the control plane.
  - **Real CPU time**, from V8's own sampling profiler over `node:inspector`.
    Built into Node, so no native dependency and nothing to compile.
  - **Samples are weighted by V8's `timeDeltas`, not `hitCount`**, so a stall
    shows up as the stall it was instead of being averaged into the nominal
    interval.
  - **`(idle)` is excluded.** Counting the event loop waiting as CPU would put
    every idle process at 100% and make the vCPU-hour figure nonsense.
  - **Fails closed**, and **clamps every bound independently of the server**
    (10–200Hz among others), so a compromised or spoofed control plane cannot
    spin a sampling loop inside the process.
  - A Node built without the inspector degrades to no profiling; everything
    else keeps working.
  - Reported overhead covers the SDK's own collection and conversion only —
    V8's in-process sampling is not observable from JavaScript, and the number
    says what it measures rather than implying it is the total.
  - Frames are `module.function`, deliberately without line numbers, so a
    function that got slower reads as the same function across a deploy.

## 0.3.1 (2026-07-22)

- Flush-failure warnings now name the endpoint they were sending to
  (`flush of N metric entries to <url> failed: ...`), so a DNS or
  connectivity failure points at the host that needs fixing instead of
  leaving the target implicit.

## 0.3.0 (2026-07-15)

- Histogram buckets on timer metrics and transaction groups: every
  duration is counted into a log2-scaled bucket (four per doubling, 128
  buckets, index 40 at 1ms) and ships as an optional `buckets` map of
  bucket index to count, alongside the existing count/sum/min/max. The
  server reads real percentiles from them instead of averages. Buckets
  merge back with the rest of an unsent aggregate on a failed flush.
- Structured log shipping: `apm.log(level, message, attrs)` and
  `apm.logger()` for level-bound `{debug, info, warn, error}` functions.
  Entries batch to `<apiUrl>/logs/ingest` on the existing flush interval,
  as a separate request with the same token auth, and carry the `trace_id`
  of the active transaction so a log line links to its trace. Messages
  truncate at 8KB; the buffer holds 500 entries and drops the oldest
  first, warning once. The target is readable as `apm.logsUrl`.
- `ROOTTRACE_APM_SERVICE_VERSION` environment fallback for
  `serviceVersion`, so deploy pipelines can report versions (deploy
  markers, regression detection) without code changes.

## 0.2.0 (2026-07-11)

- Automatic database spans (`dbInstrumentation: true`, the default):
  `mongodb` collections and cursors, `ioredis` and `redis` (v4+),
  `pg`, `mysql2`, and Elasticsearch via `@elastic/transport`. Spans are
  named by operation and target (`find app.users`, `SELECT users`,
  `GET`), never by payload; missing drivers are silent no-ops.
- Global `fetch` instrumentation: the same `http.client.*` metrics,
  `http` spans, and `traceparent` propagation as the `http`/`https`
  hooks (fetch rides undici, which those hooks never see).
- Elasticsearch's own HTTP call is folded into its db span so one query
  is one waterfall row; HTTP metrics still record.

- Kubernetes context reporting: `deployment`/`namespace` init options with
  `ROOTTRACE_APM_DEPLOYMENT`/`ROOTTRACE_APM_NAMESPACE` fallbacks, plus
  in-cluster auto-detection from the pod name and the mounted serviceaccount
  namespace.
- Request context on trace samples: the middleware records the origin IP
  (first `X-Forwarded-For` hop, socket peer as `remote_ip`), user agent,
  method, path with query string, and status code of sampled requests, and
  `Transaction.setHttp()` lets custom instrumentation attach the same.

## 0.1.0 (2026-07-08)

Initial release.

- Counters, gauges, and timers with in-memory aggregation and one ingest
  payload per flush interval.
- Transactions and spans with per-(name, type) aggregates, span breakdowns,
  and the two slowest trace samples per flush.
- Error capture with stable fingerprints.
- Express-compatible middleware with path normalization and W3C traceparent
  adoption.
- Outbound http/https auto-instrumentation with metrics, spans, and
  traceparent propagation.
- Automatic Node runtime metrics (memory, CPU, event-loop lag, GC, handles).
- 429/4xx/5xx-aware flush loop with merge-back of unsent aggregates.
