# roottrace-apm

RootTrace APM wrapper for Node.js. Aggregates metrics, transactions, errors,
trace samples, and structured logs in memory and posts them to the RootTrace
API once per flush interval. Zero runtime dependencies; Node 18+.

```
npm install roottrace-apm
```

## Quickstart

```js
const roottrace = require("roottrace-apm");

const apm = roottrace.init({
  service: "checkout-api",
  token: "rtc_...",                    // your collector token
  apiUrl: "https://api.roottrace.io/api", // optional; this is the default
  serviceVersion: "1.4.2",
});

console.log(apm.apiUrl);    // resolved API base URL (read-only)
console.log(apm.ingestUrl); // full flush target: <apiUrl>/apm/ingest
console.log(apm.logsUrl);   // log flush target: <apiUrl>/logs/ingest
```

`init()` fails fast (throws) on a missing service/token or a non-http(s)
`apiUrl`. Everything after init never throws into your application.

> **Self-hosted:** that default is RootTrace Cloud. Point it at your own
> deployment's `/api` base (or set `ROOTTRACE_API_URL` in the service's
> environment) so telemetry never leaves your network.

### Attach a version: it unlocks deploy tracking

Give each release a version and RootTrace marks the deploy on every chart,
compares the new version against the hour before it shipped, and opens an
issue if latency or errors regressed. Without a version, none of that can
happen. Either in code (`serviceVersion: "1.4.2"` above), or with no code
changes, from your deploy pipeline or Dockerfile:

```dockerfile
ARG BUILD_VERSION
ENV ROOTTRACE_APM_SERVICE_VERSION=${BUILD_VERSION}
```

built with `--build-arg BUILD_VERSION=$(git rev-parse --short HEAD)` (or a
build counter). Versions are capped at 64 characters. A build number or short
git SHA is ideal.

### Counters, gauges, timers

```js
apm.counter("orders.processed").add();
apm.counter("orders.processed", { region: "eu" }).add(3);
apm.gauge("queue.depth").set(12);

const timer = apm.timer("job.duration");
timer.record(38.2);                       // milliseconds
const result = await timer.time(async () => runJob()); // times across the await
```

Timers and transaction durations also ship a histogram alongside
count/sum/min/max, so the dashboard can show real percentiles instead of
averages. Nothing to configure: durations land in log2-scaled buckets (four
per doubling, 128 of them, ~19% wide) and go out as a `buckets` map of
bucket index to count.

### Transactions and spans

```js
// Callback style: an escaping error marks the transaction failed,
// is captured, and re-thrown unchanged.
await apm.transaction("nightly-report", { type: "task" }, async (tx) => {
  const span = tx.startSpan("SELECT orders", "db", "postgresql");
  await db.query("...");
  span.end();
});

// Manual style
const tx = apm.startTransaction("import", { type: "task" });
try {
  await doWork();
} catch (err) {
  tx.captureException(err);
  tx.setOutcome("failed");
  throw err;
} finally {
  tx.end();
}

// Handled errors anywhere; handled: false also fails the active transaction
apm.captureException(err, { handled: false });
```

### Structured logs

```js
apm.log("info", "order placed", { order_id: 4711, region: "eu" });

// or level-bound functions
const logger = apm.logger();
logger.warn("retrying payment", { attempt: 2 });
logger.error("payment failed");
```

Entries buffer and ship to `<apiUrl>/logs/ingest` on the same flush
interval as metrics, as a separate request. Each carries the service,
level, message, timestamp, optional attributes, and (inside a transaction)
its `trace_id`, so a log line links to the trace it came from. Levels are
`debug`, `info`, `warn`, and `error`; anything else records as `info`.

Messages truncate at 8KB and the buffer holds 500 entries per interval,
dropping the oldest first (warned once): logging in a hot loop costs
throughput, never memory. Like every other call after `init()`, `log()`
never throws into your application.

### Express middleware

One transaction per request, named `GET /orders/:id` (numeric, UUID, and
long-hex path segments are normalized), with `http.request.duration` and
`http.requests` metrics tagged by method and status class. Incoming W3C
`traceparent` headers are adopted for distributed tracing.

```js
const app = express();
app.use(apm.middleware());
```

### Outbound HTTP auto-instrumentation

On by default: the core `http`/`https` modules and the global `fetch`
(undici) are patched, so every outbound call reports
`http.client.duration` and `http.client.requests` tagged
`{destination: "host:port", status: "2xx"}`, becomes an `http` span when a
transaction is active, and carries a `traceparent` header. Patching those
also covers axios, got, and node-fetch. Disable with
`httpInstrumentation: false`.

### Database auto-instrumentation

Also on by default: whichever supported drivers are installed get `db`
spans inside active transactions, with no code changes. Disable with
`dbInstrumentation: false`.

- **mongodb**: collection operations and cursor drains
  (`find app.users`, `insertOne app.orders`)
- **ioredis** and **redis** (v4+): command name only (`GET`, `HSET`),
  never the key
- **pg** and **mysql2**: operation plus best-effort table
  (`SELECT users`), never the statement
- **Elasticsearch** (`@elastic/transport`): `POST /idx/_search` with
  path IDs normalized; the transport's own HTTP call is folded into the
  db span so one query is one waterfall row

## Continuous profiling

Nothing to configure here, deliberately. Profiling is turned on per service in
the RootTrace UI (**Profiling → Settings**); this SDK polls
`GET /api/apm/config` on its background flush loop and starts nothing on its
own. That means turning profiling *off* during the incident it is causing is a
toggle rather than a redeploy.

When enabled, the SDK runs **V8's own CPU profiler** over `node:inspector`
(built into Node, so no native dependency and nothing to compile) and uploads
a merged profile on each flush.

Three properties worth knowing:

- **Fails closed.** If the config cannot be fetched, profiling does not start.
- **Bounds are enforced here as well as on the server** (sample rate 10–200Hz
  among others), so a compromised or spoofed control plane cannot spin a
  sampling loop inside your process. Duplicated on purpose.
- **`apm.profiling`** reports whether the profiler is currently running.

The reported `overhead_percent` covers this SDK's own collection and conversion
work, once per upload window. V8's in-process sampling is not observable from
JavaScript and is *not* included; the number says what it measures rather than
implying it is the total.

## Configuration

| Option | Env var | Default |
| --- | --- | --- |
| `service` | `ROOTTRACE_APM_SERVICE` | required |
| `token` | `ROOTTRACE_APM_TOKEN`, then `ROOTTRACE_COLLECTOR_TOKEN` | required |
| `apiUrl` | `ROOTTRACE_API_URL` | `https://api.roottrace.io/api` |
| `intervalSeconds` | `ROOTTRACE_APM_INTERVAL_SECONDS` | `30` (clamped 5–3600) |
| `tags` | n/a | `{}` (max 8 keys, merged into every metric) |
| `runtimeMetrics` | n/a | `true` |
| `serviceVersion` | `ROOTTRACE_APM_SERVICE_VERSION` | unset (max 64 chars) |
| `httpInstrumentation` | n/a | `true` |
| `deployment` | `ROOTTRACE_APM_DEPLOYMENT` | auto-detected in Kubernetes (max 253 chars) |
| `namespace` | `ROOTTRACE_APM_NAMESPACE` | auto-detected in Kubernetes (max 253 chars) |

Inside Kubernetes (`KUBERNETES_SERVICE_HOST` set) the wrapper reports a
`kubernetes` context (deployment, namespace, and pod), deriving the
deployment from the pod name and reading the namespace from the mounted
serviceaccount when not configured explicitly. Outside Kubernetes nothing is
reported unless `deployment`/`namespace` are set. The resolved values are
readable as `apm.deployment` and `apm.namespace`.

Runtime metrics reported each flush: `process.memory.rss_bytes`,
`process.cpu.percent`, `process.uptime_seconds`, `nodejs.eventloop.lag_ms`,
`nodejs.gc.collections`, `nodejs.gc.time_ms`, `nodejs.handles.active`.

`apm.flush()` forces a flush; `apm.shutdown()` stops the loop, flushes one
last time, and clears the singleton. A best-effort shutdown also runs on
`beforeExit`. The flush timer is unref'd, so the wrapper never keeps your
process alive.

## Development

```
npm install   # installs eslint only
npm test      # node --test
npm run lint
```

## License

Apache-2.0
