"use strict";

const assert = require("node:assert/strict");
const http = require("node:http");
const os = require("node:os");
const { performance } = require("node:perf_hooks");
const { test } = require("node:test");

const mod = require("../index.js");
const {
  HttpStatusError,
  parseTraceparent,
  bucketIndex,
  MAX_ENTRIES,
  MAX_USER_ENTRIES,
  MAX_TAG_KEYS,
  MAX_TX_GROUPS,
  MAX_ERRORS,
  MAX_LOG_ENTRIES,
  MAX_LOG_MESSAGE_LENGTH,
} = mod._internals;

const VALID_TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
const NUL = "\u0000";
const key = (name, tags = "") => `${name}${NUL}${tags}`;
const txKey = (name, type = "request") => `${name}${NUL}${type}`;
const spanKey = (type, subtype = "") => `${type}${NUL}${subtype}`;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Every test drives a real singleton with a fake transport; only the
// local-server tests touch the network.
function setup(t, extra = {}) {
  const apm = mod.init({
    service: "svc",
    token: "rtc_test",
    apiUrl: "https://api.example/api",
    intervalSeconds: 5,
    runtimeMetrics: false,
    httpInstrumentation: false,
    ...extra,
  });
  const sent = [];
  apm._send = async (payload) => {
    JSON.parse(JSON.stringify(payload)); // must be serializable as-is
    sent.push(payload);
  };
  t.after(async () => {
    apm._send = async () => {};
    apm._retryAt = 0;
    await mod.shutdown();
  });
  return { apm, sent };
}

function captureLogs(t) {
  const logs = [];
  const original = console.error;
  console.error = (...args) => logs.push(args.join(" "));
  t.after(() => {
    console.error = original;
  });
  return logs;
}

function startServer(t, handler) {
  const server = http.createServer(handler);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port }));
  });
}

function get(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { headers }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () =>
        resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks).toString() })
      );
    });
    req.on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// Payload shape

test("metric payload shape matches PROTOCOL.md key for key", async (t) => {
  const { apm, sent } = setup(t);
  const orders = apm.counter("orders.processed");
  orders.add();
  orders.add(2);
  const queue = apm.gauge("queue.depth");
  queue.set(12);
  queue.set(7);
  const latency = apm.timer("http.request.duration", { endpoint: "/checkout" });
  latency.record(3.0);
  latency.record(250.0);
  latency.record(47.0);

  await apm.flush();

  assert.equal(sent.length, 1);
  const payload = sent[0];
  assert.deepEqual(
    Object.keys(payload).sort(),
    ["hostname", "interval_seconds", "language", "metrics", "runtime", "service"]
  );
  assert.equal(payload.service, "svc");
  assert.equal(payload.language, "nodejs");
  assert.equal(payload.hostname, os.hostname());
  assert.equal(payload.interval_seconds, 5);
  assert.deepEqual(Object.keys(payload.runtime).sort(), ["language_version", "pid", "wrapper_version"]);
  assert.equal(payload.runtime.pid, process.pid);
  assert.equal(payload.runtime.wrapper_version, mod.VERSION);

  const metrics = Object.fromEntries(payload.metrics.map((m) => [m.name, m]));
  assert.deepEqual(metrics["orders.processed"], {
    name: "orders.processed",
    kind: "counter",
    count: 2,
    sum: 3,
  });
  assert.deepEqual(metrics["queue.depth"], { name: "queue.depth", kind: "gauge", value: 7 });
  assert.deepEqual(metrics["http.request.duration"], {
    name: "http.request.duration",
    kind: "timer",
    unit: "ms",
    tags: { endpoint: "/checkout" },
    count: 3,
    sum: 300,
    min: 3,
    max: 250,
    buckets: { 46: 1, 62: 1, 71: 1 }, // 3ms, 47ms, 250ms
  });
});

test("full payload shape with transactions, errors, and trace samples", async (t) => {
  const { apm, sent } = setup(t, { serviceVersion: "1.2.3" });
  apm.transaction("GET /checkout", (tx) => {
    tx.startSpan("q", "db", "postgresql").end();
    try {
      throw new Error("bad");
    } catch (err) {
      apm.captureException(err);
    }
  });
  apm.counter("jobs").add();

  await apm.flush();

  const payload = sent[0];
  assert.deepEqual(
    Object.keys(payload).sort(),
    ["errors", "hostname", "interval_seconds", "language", "metrics", "runtime",
      "service", "service_version", "trace_samples", "transactions"]
  );
  assert.equal(payload.service_version, "1.2.3");

  const [txEntry] = payload.transactions;
  assert.deepEqual(
    Object.keys(txEntry).sort(),
    ["buckets", "count", "failed", "max", "min", "name", "spans", "success", "sum", "type"]
  );
  assert.equal(txEntry.name, "GET /checkout");
  assert.equal(txEntry.type, "request");
  assert.equal(txEntry.count, 1);
  assert.equal(txEntry.success, 1);
  assert.equal(txEntry.failed, 0);
  const [spanRow] = txEntry.spans;
  assert.deepEqual(Object.keys(spanRow).sort(), ["count", "subtype", "sum", "type"]);
  assert.equal(spanRow.type, "db");
  assert.equal(spanRow.subtype, "postgresql");

  const [error] = payload.errors;
  assert.deepEqual(
    Object.keys(error).sort(),
    ["count", "culprit", "fingerprint", "message", "stack", "transaction_name", "type"]
  );
  assert.equal(error.transaction_name, "GET /checkout");
  for (const frame of error.stack) {
    assert.deepEqual(Object.keys(frame).sort(), ["file", "function", "line"]);
  }

  const [sample] = payload.trace_samples;
  assert.deepEqual(
    Object.keys(sample).sort(),
    ["duration_ms", "outcome", "spans", "spans_dropped", "started_at",
      "trace_id", "transaction_name", "transaction_type"]
  );
  assert.match(sample.trace_id, /^[0-9a-f]{32}$/);
  assert.equal(sample.outcome, "success");
  const [sampleSpan] = sample.spans;
  assert.deepEqual(
    Object.keys(sampleSpan).sort(),
    ["duration_ms", "name", "start_offset_ms", "subtype", "type"]
  );
});

// ---------------------------------------------------------------------------
// Aggregation basics

test("counter resets after flush", async (t) => {
  const { apm, sent } = setup(t);
  const jobs = apm.counter("jobs");
  jobs.add();
  await apm.flush();
  jobs.add(3);
  await apm.flush();

  assert.equal(sent.length, 2);
  assert.deepEqual(sent[1].metrics, [{ name: "jobs", kind: "counter", count: 1, sum: 3 }]);
});

test("timer math and timer.time() over sync and async fns", async (t) => {
  const { apm } = setup(t);
  const timer = apm.timer("latency");
  for (const d of [5, 1.0, 9]) timer.record(d);

  const entry = apm._buffer.get(key("latency"));
  assert.equal(entry.count, 3);
  assert.equal(entry.sum, 15);
  assert.equal(entry.min, 1);
  assert.equal(entry.max, 9);

  assert.equal(timer.time(() => 7), 7);
  assert.equal(
    await timer.time(async () => {
      await sleep(20);
      return 8;
    }),
    8
  );
  const after = apm._buffer.get(key("latency"));
  assert.equal(after.count, 5);
  assert.ok(after.max >= 15, `async timing spans the await, got max ${after.max}`);
});

test("tagsKey canonicalization and escaping avoid collisions", async (t) => {
  const { apm } = setup(t);
  apm._record("hits", "counter", { b: "2", a: "1" }, null, 1);
  apm._record("hits", "counter", { a: "1", b: "2" }, null, 1);
  assert.equal(apm._buffer.get(key("hits", "a=1,b=2")).count, 2);

  // the {"a":"1,b=2"} vs {"a":"1","b":"2"} collision case
  apm._record("m", "counter", { a: "1,b=2" }, null, 1);
  apm._record("m", "counter", { a: "1", b: "2" }, null, 1);
  // '%' escapes first, so a literal "%2C" stays distinct from ","
  apm._record("m", "counter", { a: "%2C" }, null, 1);
  apm._record("m", "counter", { a: "," }, null, 1);

  const mKeys = [...apm._buffer.keys()]
    .filter((k) => k.startsWith(`m${NUL}`))
    .map((k) => k.split(NUL)[1])
    .sort();
  assert.deepEqual(mKeys, ["a=%252C", "a=%2C", "a=1%2Cb%3D2", "a=1,b=2"]);
  // tags go on the wire unescaped; only the dedup key is encoded
  assert.deepEqual(apm._buffer.get(key("m", "a=1%2Cb%3D2")).tags, { a: "1,b=2" });
});

// ---------------------------------------------------------------------------
// Histogram buckets

test("bucket index math matches the shared histogram contract", () => {
  // i = min(127, max(0, floor(log2(max(d, 0.001)) * 4) + 40))
  assert.equal(bucketIndex(1), 40);
  assert.equal(bucketIndex(1000), 79);
  assert.equal(bucketIndex(0.5), 36);
  // four buckets per doubling
  assert.equal(bucketIndex(2), 44);
  assert.equal(bucketIndex(4), 48);
  // clamped at both ends: the 0.001ms floor lands on 0, huge durations on 127
  assert.equal(bucketIndex(0), 0);
  assert.equal(bucketIndex(0.001), 0);
  assert.equal(bucketIndex(-5), 0); // negatives take the floor, never go negative
  assert.equal(bucketIndex(1e300), 127);
  assert.equal(bucketIndex(Number.MAX_VALUE), 127);
});

test("timer buckets accumulate and ride the payload as index -> count", async (t) => {
  const { apm, sent } = setup(t);
  const latency = apm.timer("latency");
  for (const d of [10, 30, 10]) latency.record(d);

  assert.deepEqual(apm._buffer.get(key("latency")).buckets, { 53: 2, 59: 1 });
  await apm.flush();

  const [metric] = sent[0].metrics;
  assert.deepEqual(metric.buckets, { 53: 2, 59: 1 });
  // stringified integer keys on the wire, counts summing to the timer count
  const wire = JSON.parse(JSON.stringify(metric)).buckets;
  assert.deepEqual(Object.keys(wire).sort(), ["53", "59"]);
  assert.equal(
    Object.values(wire).reduce((a, b) => a + b, 0),
    metric.count
  );

  // buckets reset with the rest of the aggregate
  latency.record(1);
  assert.deepEqual(apm._buffer.get(key("latency")).buckets, { 40: 1 });
});

test("counters and gauges carry no buckets", async (t) => {
  const { apm, sent } = setup(t);
  apm.counter("jobs").add();
  apm.gauge("depth").set(3);
  await apm.flush();

  for (const metric of sent[0].metrics) {
    assert.ok(!("buckets" in metric), `${metric.name} should have no buckets`);
  }
});

test("transaction groups accumulate duration buckets", async (t) => {
  const { apm, sent } = setup(t);
  // fixed durations: real timings would not land in predictable buckets
  const record = (name, duration) => {
    const tx = apm.startTransaction(name);
    apm._recordTransaction(tx, duration, "success");
    tx.closed = true;
  };
  record("job", 10);
  record("job", 10);
  record("job", 1000);

  assert.deepEqual(apm._txBuffer.get(txKey("job")).buckets, { 53: 2, 79: 1 });
  await apm.flush();

  const [group] = sent[0].transactions;
  assert.deepEqual(group.buckets, { 53: 2, 79: 1 });
  assert.equal(
    Object.values(group.buckets).reduce((a, b) => a + b, 0),
    group.count
  );
});

test("merge-back after 5xx merges timer and transaction buckets", async (t) => {
  captureLogs(t);
  const { apm, sent } = setup(t);
  const record = (duration) => {
    const tx = apm.startTransaction("job");
    apm._recordTransaction(tx, duration, "success");
    tx.closed = true;
  };
  apm.timer("latency").record(10);
  apm.timer("latency").record(30);
  record(10);

  apm._send = async () => {
    // recordings landing while the send is in flight own the live buffer,
    // so the unsent snapshot merges into them rather than replacing them
    apm.timer("latency").record(5);
    record(1000);
    throw new HttpStatusError(500, "oops");
  };
  await apm.flush();

  apm._send = async (p) => sent.push(p);
  await apm.flush();

  const [metric] = sent[0].metrics;
  assert.deepEqual(metric.buckets, { 49: 1, 53: 1, 59: 1 }); // 5ms, 10ms, 30ms
  assert.equal(metric.count, 3);
  assert.equal(
    Object.values(metric.buckets).reduce((a, b) => a + b, 0),
    metric.count
  );

  const [group] = sent[0].transactions;
  assert.deepEqual(group.buckets, { 53: 1, 79: 1 }); // 10ms, 1000ms
  assert.equal(group.count, 2);
});

test("merge-back into an untouched buffer keeps the snapshot's buckets", async (t) => {
  captureLogs(t);
  const { apm, sent } = setup(t);
  apm.timer("latency").record(10);
  apm._send = async () => {
    throw new HttpStatusError(500, "oops");
  };
  await apm.flush(); // nothing recorded meanwhile: the whole entry moves back

  apm._send = async (p) => sent.push(p);
  await apm.flush();
  assert.deepEqual(sent[0].metrics[0].buckets, { 53: 1 });
});

// ---------------------------------------------------------------------------
// Caps and sanitation

test("entry cap holds 192 user series with one throttled warning", async (t) => {
  const logs = captureLogs(t);
  const { apm } = setup(t);
  for (let i = 0; i < MAX_USER_ENTRIES + 10; i++) {
    apm._record(`m${i}`, "counter", null, null, 1);
  }
  assert.equal(apm._buffer.size, MAX_USER_ENTRIES);
  assert.equal(logs.filter((l) => l.includes("buffer full")).length, 1);
});

test("runtime metrics bypass the cap and land in the payload", async (t) => {
  const { apm, sent } = setup(t, { runtimeMetrics: true });
  for (let i = 0; i < MAX_USER_ENTRIES + 10; i++) {
    apm._record(`m${i}`, "counter", null, null, 1);
  }
  await sleep(60); // give the event-loop delay monitor a sample
  await apm.flush();

  const names = new Set(sent[0].metrics.map((m) => m.name));
  for (const name of [
    "process.memory.rss_bytes",
    "process.cpu.percent",
    "process.uptime_seconds",
    "nodejs.eventloop.lag_ms",
    "nodejs.gc.collections",
    "nodejs.gc.time_ms",
    "nodejs.handles.active",
  ]) {
    assert.ok(names.has(name), `missing runtime metric ${name}`);
  }
  assert.ok(sent[0].metrics.length <= MAX_ENTRIES);
});

test("tag key cap keeps first 8 sorted, instance tags trimmed once", async (t) => {
  const logs = captureLogs(t);
  const bigTags = {};
  for (let i = 0; i < 12; i++) bigTags[`k${i}`] = String(i);
  const { apm } = setup(t, { tags: bigTags });
  assert.equal(Object.keys(apm.tags).length, MAX_TAG_KEYS);
  assert.ok(logs.some((l) => l.includes("instance tags")));

  await mod.shutdown();
  const fresh = setup(t);
  fresh.apm._record("m", "counter", bigTags, null, 1);
  const [entry] = fresh.apm._buffer.values();
  assert.equal(Object.keys(entry.tags).length, MAX_TAG_KEYS);
  assert.deepEqual(Object.keys(entry.tags).sort(), Object.keys(bigTags).sort().slice(0, MAX_TAG_KEYS));
});

test("non-finite, empty-name, and garbage recordings drop without throwing", async (t) => {
  const logs = captureLogs(t);
  const { apm } = setup(t);
  apm.gauge("g").set(NaN);
  apm.gauge("g").set(Infinity);
  apm.counter("c").add(-Infinity);
  apm.counter("c2").add("nope");
  apm.gauge("g2").set(null);
  apm.timer("t2").record({});
  apm.counter("").add();
  apm.counter("").add();
  apm.gauge("").set(1);

  assert.equal(apm._buffer.size, 0);
  // throttled: one warning per metric name plus one for the empty name
  assert.equal(logs.filter((l) => l.includes("non-numeric")).length, 5);
  assert.equal(logs.filter((l) => l.includes("empty metric name")).length, 1);
});

test("non-string names and units are coerced, long names truncated", async (t) => {
  captureLogs(t);
  const { apm, sent } = setup(t);
  apm._record(Buffer.from("bytes.name"), "timer", null, Buffer.from("ms"), 1.5);
  apm._record(123, "counter", null, null, 1);
  apm._record("n".repeat(250), "counter", null, null, 1);

  const names = [...apm._buffer.values()].map((e) => e.name);
  assert.ok(names.every((n) => typeof n === "string"));
  assert.ok(names.some((n) => n.length === 200));
  await apm.flush();
  assert.equal(sent.length, 1); // payload survived serialization in the fake send
});

test("errors.count metric name is reserved", async (t) => {
  const logs = captureLogs(t);
  const { apm } = setup(t);
  apm.counter("errors.count").add();
  apm.counter("errors.count").add();

  assert.equal(apm._buffer.size, 0);
  assert.equal(logs.filter((l) => l.includes("reserved")).length, 1);
});

// ---------------------------------------------------------------------------
// Failure handling

test("merge-back after 5xx preserves totals across all buffers", async (t) => {
  captureLogs(t);
  const { apm, sent } = setup(t);
  const jobs = apm.counter("jobs");
  for (let i = 0; i < 5; i++) jobs.add();
  const latency = apm.timer("latency");
  latency.record(10);
  latency.record(30);
  apm.gauge("depth").set(1);
  apm.transaction("a", (tx) => tx.setOutcome("success"));
  // Five deterministic frames below the catch, so the fingerprint (which
  // hashes the innermost 5) stays stable across await boundaries.
  const d5 = () => {
    throw new TypeError("bad");
  };
  const d4 = () => d5();
  const d3 = () => d4();
  const d2 = () => d3();
  const boom = () => {
    try {
      d2();
    } catch (err) {
      apm.captureException(err);
    }
  };
  boom();

  apm._send = async () => {
    // simulate a recording landing while the send is in flight
    apm._record("depth", "gauge", null, null, 99);
    throw new HttpStatusError(500, "oops");
  };
  await apm.flush();

  jobs.add(2);
  latency.record(5);
  apm.transaction("a", (tx) => tx.setOutcome("failed"));
  boom();
  apm._send = async (p) => sent.push(p);
  await apm.flush();

  const metrics = Object.fromEntries(sent[0].metrics.map((m) => [m.name, m]));
  assert.equal(metrics.jobs.count, 6);
  assert.equal(metrics.jobs.sum, 7);
  assert.equal(metrics.latency.count, 3);
  assert.equal(metrics.latency.sum, 45);
  assert.equal(metrics.latency.min, 5);
  assert.equal(metrics.latency.max, 30);
  assert.equal(metrics.depth.value, 99); // gauge keeps the newer, in-flight value

  const [group] = sent[0].transactions;
  assert.equal(group.count, 2);
  assert.equal(group.success, 1);
  assert.equal(group.failed, 1);

  const [error] = sent[0].errors;
  assert.equal(error.count, 2); // merged additively by fingerprint

  assert.equal(sent[0].trace_samples.length, 2); // two slowest of both sets survive
  const durations = sent[0].trace_samples.map((s) => s.duration_ms);
  assert.deepEqual(durations, [...durations].sort((a, b) => b - a));
});

test("4xx drops the snapshot", async (t) => {
  const logs = captureLogs(t);
  const { apm } = setup(t);
  apm.counter("jobs").add();
  apm._send = async () => {
    throw new HttpStatusError(422, "malformed payload");
  };
  await apm.flush();

  assert.equal(apm._buffer.size, 0);
  assert.ok(logs.some((l) => l.includes("rejected")));
});

test("429 sets a deadline, merges back, and suppresses flushes until it passes", async (t) => {
  captureLogs(t);
  const { apm, sent } = setup(t);
  apm.counter("jobs").add();
  apm._send = async () => {
    throw new HttpStatusError(429, "slow down", "60");
  };
  await apm.flush();

  assert.equal(apm._buffer.get(key("jobs")).count, 1);
  assert.ok(apm._retryAt > Date.now());
  apm._send = async (p) => sent.push(p);
  await apm.flush();
  assert.deepEqual(sent, []);

  apm._retryAt = 0;
  await apm.flush();
  assert.equal(sent.length, 1);
});

test("unserializable payloads are dropped, never merged back", async (t) => {
  const logs = captureLogs(t);
  const { apm } = setup(t);
  apm.counter("jobs").add();
  // force a poison entry; JSON.stringify throws on BigInt
  apm._buffer.set(key("poison"), { name: "poison", kind: "gauge", unit: null, tags: {}, value: 1n });
  delete apm._send; // use the real send: stringify happens before any network I/O
  await apm.flush();

  assert.equal(apm._buffer.size, 0);
  assert.ok(logs.some((l) => l.includes("unserializable")));
});

test("merge-back tolerates a kind change mid-flight", async (t) => {
  const logs = captureLogs(t);
  const { apm } = setup(t);
  apm.counter("m").add();
  apm._send = async () => {
    apm._record("m", "gauge", null, null, 5);
    throw new HttpStatusError(500, "oops");
  };
  await apm.flush();

  const entry = apm._buffer.get(key("m"));
  assert.equal(entry.kind, "gauge");
  assert.equal(entry.value, 5);
  assert.ok(logs.some((l) => l.includes("changed kind")));
});

// ---------------------------------------------------------------------------
// Transactions and spans

test("transaction aggregation, escaping error captured and re-thrown", async (t) => {
  const { apm } = setup(t);
  for (let i = 0; i < 2; i++) {
    apm.transaction("GET /checkout", (tx) => {
      tx.startSpan("q", "db", "postgresql").end();
    });
  }
  const original = new Error("invalid order id");
  assert.throws(
    () =>
      apm.transaction("GET /checkout", () => {
        throw original;
      }),
    (err) => err === original // re-thrown unchanged
  );

  const group = apm._txBuffer.get(txKey("GET /checkout"));
  assert.equal(group.count, 3);
  assert.equal(group.success, 2);
  assert.equal(group.failed, 1);
  assert.ok(group.min <= group.max);
  const breakdown = group.spans.get(spanKey("db", "postgresql"));
  assert.equal(breakdown.count, 2);

  const [error] = apm._errorBuffer.values();
  assert.equal(error.type, "Error");
  assert.equal(error.transaction_name, "GET /checkout");
});

test("async transaction fn spans the await and keeps its spans", async (t) => {
  const { apm } = setup(t);
  const result = await apm.transaction("async-job", { type: "task" }, async (tx) => {
    await sleep(25);
    tx.startSpan("q", "db").end();
    return 7;
  });
  assert.equal(result, 7);

  const group = apm._txBuffer.get(txKey("async-job", "task"));
  assert.equal(group.count, 1);
  assert.equal(group.success, 1);
  assert.ok(group.sum >= 15, `timed across the await, got ${group.sum}ms`);
  assert.equal(group.spans.get(spanKey("db")).count, 1);
});

test("async transaction rejection marks failed and re-throws", async (t) => {
  const { apm } = setup(t);
  await assert.rejects(
    apm.transaction("async-bad", { type: "task" }, async () => {
      throw new RangeError("k");
    }),
    RangeError
  );
  assert.equal(apm._txBuffer.get(txKey("async-bad", "task")).failed, 1);
  const [error] = apm._errorBuffer.values();
  assert.equal(error.type, "RangeError");
});

test("interleaved async transactions keep their own spans", async (t) => {
  const { apm } = setup(t);
  const work = (name, delay) =>
    apm.transaction(name, { type: "task" }, async (tx) => {
      const span = tx.startSpan("op", "db");
      await sleep(delay);
      span.end();
    });
  await Promise.all([work("quick", 5), work("slow", 60)]);

  const quick = apm._txBuffer.get(txKey("quick", "task")).spans.get(spanKey("db"));
  const slow = apm._txBuffer.get(txKey("slow", "task")).spans.get(spanKey("db"));
  assert.equal(quick.count, 1);
  assert.equal(slow.count, 1);
  assert.ok(quick.sum < slow.sum);
});

test("startTransaction manual lifecycle with setOutcome and captureException", async (t) => {
  const { apm } = setup(t);
  const tx = apm.startTransaction("job", { type: "task" });
  tx.captureException(new Error("partial failure"));
  tx.setOutcome("failed");
  tx.end();
  tx.end(); // double end is a no-op

  const group = apm._txBuffer.get(txKey("job", "task"));
  assert.equal(group.count, 1);
  assert.equal(group.failed, 1);
  const [error] = apm._errorBuffer.values();
  assert.equal(error.transaction_name, "job");
});

test("closed transactions are treated as absent by every attach path", async (t) => {
  const { apm } = setup(t);
  const tx = apm.startTransaction("first");
  const late = tx.startSpan("late");
  tx.end();
  late.end(); // after close: no-op
  tx.startSpan("later", "db").end(); // started after close: no-op

  assert.equal(apm._txBuffer.get(txKey("first")).spans.size, 0);
  const [sample] = apm._traceSamples;
  assert.deepEqual(sample.spans, []);

  // captureException(handled=false) with only a closed tx active does not fail it
  apm.captureException(new Error("x"), { handled: false });
  assert.equal(apm._txBuffer.get(txKey("first")).failed, 0);
});

test("unhandled captureException marks the active transaction failed", async (t) => {
  const { apm } = setup(t);
  apm.transaction("risky", () => {
    try {
      throw new Error("boom");
    } catch (err) {
      apm.captureException(err, { handled: false });
    }
  });
  const group = apm._txBuffer.get(txKey("risky"));
  assert.equal(group.failed, 1);
  assert.equal(group.success, 0);
  const [sample] = apm._traceSamples;
  assert.equal(sample.outcome, "failed");

  apm.transaction("fine", () => {
    try {
      throw new Error("boom");
    } catch (err) {
      apm.captureException(err); // handled: outcome unchanged
    }
  });
  assert.equal(apm._txBuffer.get(txKey("fine")).success, 1);
});

test("trace samples keep the two slowest; group cap 100 throttled", async (t) => {
  const logs = captureLogs(t);
  const { apm } = setup(t);
  const record = (name, duration) => {
    const tx = apm.startTransaction(name);
    apm._recordTransaction(tx, duration, "success");
    tx.closed = true;
  };
  record("a", 10);
  record("b", 50);
  record("c", 30);
  record("d", 20);
  const durations = apm._traceSamples.map((s) => s.duration_ms).sort((x, y) => x - y);
  assert.deepEqual(durations, [30, 50]);

  for (let i = 0; i < MAX_TX_GROUPS + 5; i++) record(`t${i}`, 1);
  assert.equal(apm._txBuffer.size, MAX_TX_GROUPS);
  assert.equal(logs.filter((l) => l.includes("transaction buffer full")).length, 1);
});

test("transaction and span names are sanitized and clipped", async (t) => {
  const { apm } = setup(t);
  apm.transaction("", { type: "" }, (tx) => {
    tx.startSpan("", "", "").end();
    tx.startSpan("q", "x".repeat(60)).end();
  });
  apm.transaction(123, { type: 456 }, () => {});

  const group = apm._txBuffer.get(txKey("unnamed"));
  assert.equal(group.spans.get(spanKey("custom")).count, 1);
  assert.ok(group.spans.has(spanKey("x".repeat(40))));
  assert.ok(apm._txBuffer.has(txKey("123", "456")));
});

// ---------------------------------------------------------------------------
// Errors

test("fingerprint is deterministic, message truncated, frames outermost-first", async (t) => {
  const { apm } = setup(t);
  function thrower(message) {
    try {
      throw new SyntaxError(message);
    } catch (err) {
      apm.captureException(err);
    }
  }
  thrower("boom");
  thrower("boom");
  thrower("x".repeat(5000));

  assert.equal(apm._errorBuffer.size, 1); // same type/culprit/frames, same fingerprint
  const [error] = apm._errorBuffer.values();
  assert.match(error.fingerprint, /^[0-9a-f]{16}$/);
  assert.equal(error.count, 3);
  assert.equal(error.type, "SyntaxError");
  assert.equal(error.message, "boom"); // kept entry's message, only count grows
  // V8 stacks are innermost-first; the wire format is outermost-first
  assert.equal(error.stack[error.stack.length - 1].function, "thrower");
  assert.ok(error.culprit.endsWith(".thrower"));
  for (const frame of error.stack) {
    assert.ok(frame.function.length <= 300);
    assert.ok(frame.file.length <= 1024);
    assert.ok(Number.isInteger(frame.line));
  }
});

test("long messages truncate at 1000 chars", async (t) => {
  const { apm } = setup(t);
  try {
    throw new Error("x".repeat(5000));
  } catch (err) {
    apm.captureException(err);
  }
  const [error] = apm._errorBuffer.values();
  assert.equal(error.message.length, 1000);
});

test("error cap at 25 distinct fingerprints, counts preserved on kept ones", async (t) => {
  const logs = captureLogs(t);
  const { apm } = setup(t);
  const capture = (i) => {
    try {
      // distinct messages share a fingerprint; distinct types do not
      const err = new Error("e");
      err.name = `Err${i}`;
      throw err;
    } catch (err) {
      apm.captureException(err);
    }
  };
  for (let i = 0; i < MAX_ERRORS + 5; i++) capture(i);
  capture(0); // repeats on kept errors still count

  assert.equal(apm._errorBuffer.size, MAX_ERRORS);
  assert.equal(logs.filter((l) => l.includes("error buffer full")).length, 1);
  const first = apm._errorBuffer.values().next().value;
  assert.equal(first.count, 2);
});

test("captureException never throws on garbage input", async (t) => {
  const logs = captureLogs(t);
  const { apm } = setup(t);
  apm.captureException("just a string");
  apm.captureException(null);
  apm.captureException(42);
  assert.equal(apm._errorBuffer.size, 0);
  assert.equal(logs.filter((l) => l.includes("non-Error")).length, 1); // throttled
});

// ---------------------------------------------------------------------------
// Structured logs

// Records every send as {payload, url} so the metric and log requests can
// be told apart by target.
function captureSends(apm) {
  const sends = [];
  apm._send = async (payload, url) => {
    JSON.parse(JSON.stringify(payload)); // must be serializable as-is
    sends.push({ payload, url });
  };
  return sends;
}

test("logs batch to /logs/ingest on the flush interval, separate from metrics", async (t) => {
  const { apm } = setup(t);
  const sends = captureSends(apm);
  assert.equal(apm.logsUrl, "https://api.example/api/logs/ingest");

  apm.counter("jobs").add();
  apm.log("info", "started", { region: "eu" });
  apm.log("error", "boom");
  await apm.flush();

  assert.equal(sends.length, 2);
  const [metricSend, logSend] = sends;
  assert.equal(metricSend.url, apm.ingestUrl);
  assert.ok(!("logs" in metricSend.payload)); // logs never ride the metric payload
  assert.equal(logSend.url, apm.logsUrl);
  assert.deepEqual(Object.keys(logSend.payload), ["logs"]);

  const [first, second] = logSend.payload.logs;
  assert.deepEqual(Object.keys(first).sort(), ["attrs", "level", "message", "service", "timestamp"]);
  assert.equal(first.service, "svc");
  assert.equal(first.level, "info");
  assert.equal(first.message, "started");
  assert.deepEqual(first.attrs, { region: "eu" });
  assert.match(first.timestamp, /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/);
  assert.equal(second.level, "error");
  assert.ok(!("attrs" in second)); // omitted when absent
  assert.ok(!("trace_id" in second)); // no active transaction

  // the buffer drains with the flush
  assert.deepEqual(apm._logBuffer, []);
  await apm.flush();
  assert.equal(sends.length, 2); // nothing buffered: no second log request
});

test("logs pick up the active transaction's trace id", async (t) => {
  const { apm } = setup(t);
  let traceId;
  apm.transaction("GET /checkout", (tx) => {
    traceId = tx.traceId;
    apm.log("info", "inside");
  });
  apm.log("info", "outside");

  const [inside, outside] = apm._logBuffer;
  assert.equal(inside.trace_id, traceId);
  assert.match(inside.trace_id, /^[0-9a-f]{32}$/);
  assert.ok(!("trace_id" in outside)); // the transaction closed: treated as absent
});

test("logger() returns bound level functions", async (t) => {
  const { apm } = setup(t);
  const logger = apm.logger();
  assert.deepEqual(Object.keys(logger).sort(), ["debug", "error", "info", "warn"]);
  logger.debug("d");
  logger.info("i", { a: 1 });
  logger.warn("w");
  logger.error("e");

  assert.deepEqual(
    apm._logBuffer.map((entry) => [entry.level, entry.message]),
    [["debug", "d"], ["info", "i"], ["warn", "w"], ["error", "e"]]
  );
  assert.deepEqual(apm._logBuffer[1].attrs, { a: 1 });

  // detached from the instance: bound functions keep working
  const { info } = logger;
  info("detached");
  assert.equal(apm._logBuffer[4].message, "detached");
});

test("log messages truncate at 8KB with one throttled warning", async (t) => {
  const logs = captureLogs(t);
  const { apm } = setup(t);
  apm.log("info", "x".repeat(MAX_LOG_MESSAGE_LENGTH + 5000));
  apm.log("info", "y".repeat(MAX_LOG_MESSAGE_LENGTH + 1));
  apm.log("info", "z".repeat(MAX_LOG_MESSAGE_LENGTH)); // exactly at the cap: untouched

  assert.equal(apm._logBuffer[0].message.length, MAX_LOG_MESSAGE_LENGTH);
  assert.equal(apm._logBuffer[1].message.length, MAX_LOG_MESSAGE_LENGTH);
  assert.equal(apm._logBuffer[2].message, "z".repeat(MAX_LOG_MESSAGE_LENGTH));
  assert.equal(logs.filter((l) => l.includes("log message longer")).length, 1);
});

test("log buffer caps at 500, dropping oldest, with one throttled warning", async (t) => {
  const logs = captureLogs(t);
  const { apm } = setup(t);
  for (let i = 0; i < MAX_LOG_ENTRIES + 10; i++) apm.log("info", `m${i}`);

  assert.equal(apm._logBuffer.length, MAX_LOG_ENTRIES);
  // drop-oldest: the newest entries survive
  assert.equal(apm._logBuffer[0].message, "m10");
  assert.equal(apm._logBuffer[MAX_LOG_ENTRIES - 1].message, `m${MAX_LOG_ENTRIES + 9}`);
  assert.equal(logs.filter((l) => l.includes("log buffer full")).length, 1);
});

test("unknown levels fall back to info, garbage never throws", async (t) => {
  const logs = captureLogs(t);
  const { apm } = setup(t);
  apm.log("trace", "unknown level");
  apm.log("FATAL", "also unknown");
  apm.log("WARN", "case-insensitive"); // normalized, not a fallback
  apm.log(null, "null level");
  apm.log("info", { a: 1 });
  apm.log("info", "attrs garbage", "not an object");
  apm.log("info", "null attrs", null);

  const levels = apm._logBuffer.map((entry) => entry.level);
  assert.deepEqual(levels, ["info", "info", "warn", "info", "info", "info", "info"]);
  assert.equal(apm._logBuffer[4].message, "[object Object]");
  assert.ok(!("attrs" in apm._logBuffer[5])); // non-objects are ignored
  assert.ok(!("attrs" in apm._logBuffer[6]));
  assert.ok(logs.some((l) => l.includes("unknown log level")));
});

test("empty messages drop rather than fail the batch", async (t) => {
  const logs = captureLogs(t);
  const { apm } = setup(t);
  // the server rejects message "" and would 422 the whole batch with it
  apm.log("info", "");
  apm.log("info", undefined);
  apm.log("info", null);
  apm.log("error", "kept");

  assert.deepEqual(apm._logBuffer.map((e) => e.message), ["kept"]);
  assert.equal(logs.filter((l) => l.includes("empty message")).length, 1); // throttled
});

test("logs merge back on send failure, newest kept at the cap", async (t) => {
  const logs = captureLogs(t);
  const { apm } = setup(t);
  apm.log("info", "first");
  apm._send = async (payload) => {
    if (payload.logs) {
      // a log recorded while the send is in flight lands in the live buffer
      apm.log("info", "in-flight");
      throw new HttpStatusError(500, "oops");
    }
  };
  await apm.flush();

  // unsent entries go back in front of the live ones, oldest first
  assert.deepEqual(apm._logBuffer.map((e) => e.message), ["first", "in-flight"]);

  const sends = captureSends(apm);
  await apm.flush();
  assert.deepEqual(
    sends.find((s) => s.url === apm.logsUrl).payload.logs.map((e) => e.message),
    ["first", "in-flight"]
  );

  // at the cap the merge-back drops the oldest, which the snapshot holds
  for (let i = 0; i < MAX_LOG_ENTRIES; i++) apm.log("info", `m${i}`);
  apm._mergeBackLogs([{ message: "ancient" }]);
  assert.equal(apm._logBuffer.length, MAX_LOG_ENTRIES);
  assert.equal(apm._logBuffer[0].message, "m0"); // "ancient" was the oldest and fell off
  assert.equal(apm._logBuffer[MAX_LOG_ENTRIES - 1].message, `m${MAX_LOG_ENTRIES - 1}`);
  assert.ok(logs.some((l) => l.includes("unsent log entries")));
});

test("4xx drops the log batch; 429 holds it behind the deadline", async (t) => {
  const logs = captureLogs(t);
  const { apm } = setup(t);
  apm.log("info", "rejected");
  apm._send = async (payload) => {
    if (payload.logs) throw new HttpStatusError(422, "malformed");
  };
  await apm.flush();
  assert.deepEqual(apm._logBuffer, []); // resending would fail forever
  assert.ok(logs.some((l) => l.includes("log entries rejected")));

  apm.log("info", "rate limited");
  apm._send = async (payload) => {
    if (payload.logs) throw new HttpStatusError(429, "slow down", "60");
  };
  await apm.flush();
  assert.equal(apm._logBuffer.length, 1);
  assert.ok(apm._retryAt > Date.now());

  // behind the deadline nothing sends, and the logs stay buffered
  const sends = captureSends(apm);
  await apm.flush();
  assert.deepEqual(sends, []);
  assert.equal(apm._logBuffer.length, 1);

  apm._retryAt = 0;
  await apm.flush();
  assert.equal(sends.length, 1);
  assert.equal(sends[0].url, apm.logsUrl);
});

test("a metric 429 holds the log batch back with it", async (t) => {
  captureLogs(t);
  const { apm } = setup(t);
  apm.counter("jobs").add();
  apm.log("info", "held");
  let logSends = 0;
  apm._send = async (payload) => {
    if (payload.logs) logSends++;
    else throw new HttpStatusError(429, "slow down", "60");
  };
  await apm.flush();

  assert.equal(logSends, 0); // the log request never went out
  assert.deepEqual(apm._logBuffer.map((e) => e.message), ["held"]);
});

test("log() never throws on unserializable attrs; the batch is dropped", async (t) => {
  const logs = captureLogs(t);
  const { apm } = setup(t);
  apm.log("info", "poison", { big: 1n }); // JSON.stringify throws on BigInt
  delete apm._send; // the real send: stringify happens before any network I/O
  await apm.flush();

  assert.deepEqual(apm._logBuffer, []); // dropped, never merged back
  assert.ok(logs.some((l) => l.includes("unserializable log entries")));
});

// ---------------------------------------------------------------------------
// Traceparent

test("traceparent parse accept/reject table", () => {
  const traceId = "0af7651916cd43dd8448eb211c80319c";
  assert.equal(parseTraceparent(VALID_TRACEPARENT), traceId);
  // case-insensitive, normalized to lowercase
  assert.equal(parseTraceparent(VALID_TRACEPARENT.toUpperCase()), traceId);
  // future versions parse, with or without extra fields (W3C SHOULD)
  assert.equal(parseTraceparent(`01-${traceId}-b7ad6b7169203331-01`), traceId);
  assert.equal(parseTraceparent(`cc-${traceId}-b7ad6b7169203331-01-extra-state`), traceId);
  for (const bad of [
    null,
    undefined,
    42,
    "",
    "nonsense",
    "00-short-b7ad6b7169203331-01",
    `ff-${traceId}-b7ad6b7169203331-01`, // version ff is forbidden
    `00-${traceId}-b7ad6b7169203331-01-extra`, // version 00 has no suffix
    `00-${"0".repeat(32)}-b7ad6b7169203331-01`, // all-zero trace id
    `00-${traceId}-${"0".repeat(16)}-01`, // all-zero parent id
  ]) {
    assert.equal(parseTraceparent(bad), null, String(bad));
  }
});

test("transactions adopt a valid traceparent, mint otherwise", async (t) => {
  const { apm } = setup(t);
  let minted, adopted;
  apm.transaction("t", (tx) => {
    minted = tx.traceId;
  });
  apm.transaction("t", { traceparent: VALID_TRACEPARENT }, (tx) => {
    adopted = tx.traceId;
  });
  assert.match(minted, /^[0-9a-f]{32}$/);
  assert.equal(adopted, "0af7651916cd43dd8448eb211c80319c");
});

// ---------------------------------------------------------------------------
// Config and endpoints

test("init fails fast and exposes read-only url getters", async (t) => {
  assert.throws(() => mod.init({ token: "rtc_t", httpInstrumentation: false }), /service/);
  assert.throws(() => mod.init({ service: "svc", httpInstrumentation: false }), /token/);
  assert.throws(
    () => mod.init({ service: "svc", token: "rtc_t", apiUrl: "ftp://api.example" }),
    /http\(s\)/
  );
  assert.throws(
    () => mod.init({ service: "svc", token: "rtc_t", apiUrl: "not a url" }),
    /http\(s\)/
  );

  const logs = captureLogs(t);
  const { apm } = setup(t, {
    apiUrl: "http://api.example/api/",
    service: "s".repeat(200),
    serviceVersion: "v".repeat(100),
    intervalSeconds: 2,
  });
  assert.equal(apm.apiUrl, "http://api.example/api");
  assert.equal(apm.ingestUrl, "http://api.example/api/apm/ingest");
  assert.throws(() => {
    "use strict";
    apm.apiUrl = "https://elsewhere.example";
  }, TypeError);
  assert.equal(apm.service, "s".repeat(160));
  assert.equal(apm.serviceVersion, "v".repeat(64));
  assert.equal(apm.intervalSeconds, 5); // clamped to the server's minimum

  const again = mod.init({ service: "other", token: "x" });
  assert.equal(again, apm); // second init warns and returns the existing instance
  assert.ok(logs.some((l) => l.includes("again")));
});

test("env fallbacks with defensive interval parse", async (t) => {
  process.env.ROOTTRACE_APM_SERVICE = "env-svc";
  process.env.ROOTTRACE_COLLECTOR_TOKEN = "rtc_env";
  process.env.ROOTTRACE_APM_INTERVAL_SECONDS = "garbage";
  t.after(() => {
    delete process.env.ROOTTRACE_APM_SERVICE;
    delete process.env.ROOTTRACE_COLLECTOR_TOKEN;
    delete process.env.ROOTTRACE_APM_INTERVAL_SECONDS;
  });
  captureLogs(t);
  const { apm } = setup(t, { service: undefined, token: undefined, intervalSeconds: undefined });
  assert.equal(apm.service, "env-svc");
  assert.equal(apm.token, "rtc_env");
  assert.equal(apm.intervalSeconds, 30);
  assert.equal(apm.apiUrl, "https://api.example/api");
});

// ---------------------------------------------------------------------------
// Middleware, end to end

test("middleware names, adopts traceparent, marks 5xx failed, records metrics", async (t) => {
  const { apm } = setup(t);
  const mw = apm.middleware();
  const { port } = await startServer(t, (req, res) => {
    mw(req, res, () => {
      res.statusCode = req.url.startsWith("/boom") ? 500 : 200;
      res.end("ok");
    });
  });

  const ok = await get(
    `http://127.0.0.1:${port}/orders/123/items/550e8400-e29b-41d4-a716-446655440000`
  );
  assert.equal(ok.statusCode, 200);
  await get(`http://127.0.0.1:${port}/orders/665f1c2b9a8d4e0012345678/report?full=1`);
  await get(`http://127.0.0.1:${port}/boom`);
  await sleep(20); // let the finish listeners run

  const group = apm._txBuffer.get(txKey("GET /orders/:id/items/:id"));
  assert.equal(group.count, 1);
  assert.equal(group.success, 1);
  assert.ok(apm._txBuffer.has(txKey("GET /orders/:id/report"))); // dashless hex + query stripped

  const boom = apm._txBuffer.get(txKey("GET /boom"));
  assert.equal(boom.failed, 1);
  assert.equal(boom.success, 0);

  const okTags = "method=GET,status=2xx";
  assert.equal(apm._buffer.get(key("http.request.duration", okTags)).count, 2);
  assert.equal(apm._buffer.get(key("http.requests", okTags)).count, 2);
  assert.equal(apm._buffer.get(key("http.requests", "method=GET,status=5xx")).count, 1);
});

test("middleware adopts a valid incoming traceparent", async (t) => {
  const { apm } = setup(t);
  const mw = apm.middleware();
  const { port } = await startServer(t, (req, res) => {
    mw(req, res, () => res.end("ok"));
  });
  await get(`http://127.0.0.1:${port}/one`, { traceparent: VALID_TRACEPARENT.toUpperCase() });
  await get(`http://127.0.0.1:${port}/two`, { traceparent: "00-not-a-trace-id-01" });
  await sleep(20);

  const byName = Object.fromEntries(apm._traceSamples.map((s) => [s.transaction_name, s]));
  assert.equal(byName["GET /one"].trace_id, "0af7651916cd43dd8448eb211c80319c");
  assert.match(byName["GET /two"].trace_id, /^[0-9a-f]{32}$/); // malformed: minted instead
  assert.notEqual(byName["GET /two"].trace_id, "0af7651916cd43dd8448eb211c80319c");
});

test("middleware captures request context on the trace sample", async (t) => {
  const { apm } = setup(t);
  const mw = apm.middleware();
  const { port } = await startServer(t, (req, res) => {
    mw(req, res, () => {
      res.statusCode = 404;
      res.end("nope");
    });
  });
  await get(`http://127.0.0.1:${port}/orders/7?page=2`, {
    "x-forwarded-for": "203.0.113.7, 10.0.0.1",
    "user-agent": "node-test-agent",
  });
  await sleep(20);

  const [sample] = apm._traceSamples;
  assert.deepEqual(sample.http, {
    method: "GET",
    path: "/orders/7?page=2", // the real path, query included
    client_ip: "203.0.113.7", // first X-Forwarded-For hop
    remote_ip: "127.0.0.1", // the socket peer, kept alongside
    user_agent: "node-test-agent",
    status_code: 404,
  });
});

test("middleware without proxy headers uses the socket peer address", async (t) => {
  const { apm } = setup(t);
  const mw = apm.middleware();
  const { port } = await startServer(t, (req, res) => {
    mw(req, res, () => res.end("ok"));
  });
  await get(`http://127.0.0.1:${port}/plain`);
  await sleep(20);

  const [sample] = apm._traceSamples;
  assert.equal(sample.http.client_ip, "127.0.0.1");
  assert.equal(sample.http.remote_ip, "127.0.0.1"); // always the socket peer
  assert.equal(sample.http.user_agent, undefined);
  assert.equal(sample.http.status_code, 200);
  assert.equal(sample.http.path, "/plain");
});

test("setHttp on a manual transaction reaches the trace sample", async (t) => {
  const { apm, sent } = setup(t);
  apm.transaction("consume orders", { type: "task" }, (tx) => {
    tx.setHttp({ clientIp: "198.51.100.4", method: "GET", path: "/queue", statusCode: 200 });
  });
  await apm.flush();

  const [sample] = sent[0].trace_samples;
  assert.deepEqual(sample.http, {
    method: "GET",
    path: "/queue",
    client_ip: "198.51.100.4",
    status_code: 200,
  });
});

test("middleware never throws into the app on garbage requests", async (t) => {
  captureLogs(t);
  const { apm } = setup(t);
  const mw = apm.middleware();
  let called = 0;
  // no headers object, no url: the middleware must still call next once
  mw({ method: null, url: null }, { statusCode: 200, on: () => {} }, () => called++);
  assert.equal(called, 1);
});

// ---------------------------------------------------------------------------
// Outbound instrumentation, end to end

test("outbound http calls record metrics, spans, and deliver a traceparent", async (t) => {
  const { apm } = setup(t, { httpInstrumentation: true });
  mod._internals.instrumentHttp();
  const before = http.request;
  mod._internals.instrumentHttp(); // idempotent: no double patch
  assert.equal(http.request, before);

  const received = [];
  const { port } = await startServer(t, (req, res) => {
    received.push({ ...req.headers });
    res.end("ok");
  });
  const destination = `127.0.0.1:${port}`;

  let traceId;
  await apm.transaction("GET /outbound", async (tx) => {
    traceId = tx.traceId;
    const res = await get(`http://${destination}/data`);
    assert.equal(res.body, "ok");
  });

  const [headers] = received;
  assert.match(headers.traceparent, new RegExp(`^00-${traceId}-[0-9a-f]{16}-01$`));

  const tags = `destination=${destination},status=2xx`;
  const timerEntry = apm._buffer.get(key("http.client.duration", tags));
  assert.equal(timerEntry.kind, "timer");
  assert.equal(timerEntry.count, 1);
  assert.deepEqual(timerEntry.tags, { destination, status: "2xx" });
  assert.equal(apm._buffer.get(key("http.client.requests", tags)).count, 1);

  const group = apm._txBuffer.get(txKey("GET /outbound"));
  assert.equal(group.spans.get(spanKey("http", destination)).count, 1);
  const [sample] = apm._traceSamples;
  const [httpSpan] = sample.spans;
  assert.equal(httpSpan.name, `GET ${destination}`);
  assert.equal(httpSpan.subtype, destination);
});

test("a caller-set traceparent is not overwritten", async (t) => {
  const { apm } = setup(t, { httpInstrumentation: true });
  const received = [];
  const { port } = await startServer(t, (req, res) => {
    received.push(req.headers.traceparent);
    res.end("ok");
  });
  await apm.transaction("GET /manual", async () => {
    await get(`http://127.0.0.1:${port}/`, { traceparent: VALID_TRACEPARENT });
  });
  assert.deepEqual(received, [VALID_TRACEPARENT]);
});

test("failed outbound calls record status=error", async (t) => {
  const { apm } = setup(t, { httpInstrumentation: true });
  // grab a port nothing listens on
  const { server, port } = await startServer(t, () => {});
  await new Promise((resolve) => server.close(resolve));

  const destination = `127.0.0.1:${port}`;
  await apm.transaction("GET /down", async () => {
    await assert.rejects(get(`http://${destination}/`));
  });

  const tags = `destination=${destination},status=error`;
  assert.equal(apm._buffer.get(key("http.client.requests", tags)).count, 1);
  assert.equal(apm._buffer.get(key("http.client.duration", tags)).count, 1);
  const group = apm._txBuffer.get(txKey("GET /down"));
  assert.equal(group.spans.get(spanKey("http", destination)).count, 1);
});

test("the wrapper's own flush traffic is never instrumented", async (t) => {
  const bodies = [];
  const { port } = await startServer(t, (req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      bodies.push({
        url: req.url,
        auth: req.headers.authorization,
        agent: req.headers["user-agent"],
        payload: JSON.parse(Buffer.concat(chunks).toString()),
      });
      res.end("{}");
    });
  });

  const apm = mod.init({
    service: "svc",
    token: "rtc_test",
    apiUrl: `http://127.0.0.1:${port}/api`,
    intervalSeconds: 5,
    runtimeMetrics: false,
    httpInstrumentation: true,
  });
  t.after(() => mod.shutdown());

  apm.counter("jobs").add();
  await apm.flush(); // real transport, straight at the local server

  assert.equal(bodies.length, 1);
  assert.equal(bodies[0].url, "/api/apm/ingest");
  assert.equal(bodies[0].auth, "Collector rtc_test");
  assert.equal(bodies[0].agent, `roottrace-apm-node/${mod.VERSION}`);
  assert.deepEqual(bodies[0].payload.metrics, [{ name: "jobs", kind: "counter", count: 1, sum: 1 }]);
  // the flush itself produced no http.client.* series
  const clientKeys = [...apm._buffer.keys()].filter((k) => k.startsWith("http.client"));
  assert.deepEqual(clientKeys, []);
});

test("sum overflow is clamped instead of reaching the wire as null", async (t) => {
  const { apm, sent } = setup(t);
  const huge = 1.7e308;
  apm.timer("t.overflow").record(huge);
  apm.timer("t.overflow").record(huge); // would overflow to Infinity unclamped
  apm.counter("c.overflow").add(huge);
  apm.counter("c.overflow").add(huge);
  await apm.flush();
  const byName = Object.fromEntries(sent[0].metrics.map((m) => [m.name, m]));
  assert.equal(byName["t.overflow"].count, 2);
  assert.equal(byName["t.overflow"].sum, huge); // second add kept the previous sum
  assert.ok(Number.isFinite(byName["c.overflow"].sum));
  assert.ok(!JSON.stringify(sent[0]).includes('"sum":null'));
});

// ---------------------------------------------------------------------------
// Kubernetes context

const K8S_POD = "checkout-api-7d9f8b6c5d-x2k4p";
const K8S_ENV_KEYS = [
  "KUBERNETES_SERVICE_HOST",
  "ROOTTRACE_APM_DEPLOYMENT",
  "ROOTTRACE_APM_NAMESPACE",
];

// Clears the Kubernetes-related env vars (so nothing leaks in from the
// host), applies the overrides, and restores everything after the test.
function k8sEnv(t, overrides = {}) {
  const saved = {};
  for (const key of K8S_ENV_KEYS) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
  for (const [key, value] of Object.entries(overrides)) process.env[key] = value;
  t.after(() => {
    for (const key of K8S_ENV_KEYS) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  });
}

test("explicit env vars win over in-cluster detection", async (t) => {
  k8sEnv(t, {
    KUBERNETES_SERVICE_HOST: "10.0.0.1",
    ROOTTRACE_APM_DEPLOYMENT: " checkout ",
    ROOTTRACE_APM_NAMESPACE: "prod",
  });
  t.mock.method(os, "hostname", () => K8S_POD);
  const { apm, sent } = setup(t);
  assert.equal(apm.deployment, "checkout"); // trimmed, not derived
  assert.equal(apm.namespace, "prod");
  apm.counter("jobs").add();
  await apm.flush();
  assert.deepEqual(sent[0].kubernetes, {
    deployment: "checkout",
    namespace: "prod",
    pod: K8S_POD,
  });
});

test("in-cluster deployment derived from a ReplicaSet pod name", async (t) => {
  k8sEnv(t, { KUBERNETES_SERVICE_HOST: "10.0.0.1" });
  t.mock.method(os, "hostname", () => K8S_POD);
  const { apm, sent } = setup(t);
  assert.equal(apm.deployment, "checkout-api");
  apm.counter("jobs").add();
  await apm.flush();
  assert.equal(sent[0].kubernetes.deployment, "checkout-api");
  assert.equal(sent[0].kubernetes.pod, K8S_POD);
  // the serviceaccount namespace file is unreadable here
  assert.ok(!("namespace" in sent[0].kubernetes));
});

test("in-cluster deployment derived from a StatefulSet pod name", async (t) => {
  k8sEnv(t, { KUBERNETES_SERVICE_HOST: "10.0.0.1" });
  t.mock.method(os, "hostname", () => "kafka-2");
  const { apm } = setup(t);
  assert.equal(apm.deployment, "kafka");
});

test("in-cluster pod name matching neither pattern is sent as-is", async (t) => {
  k8sEnv(t, { KUBERNETES_SERVICE_HOST: "10.0.0.1" });
  t.mock.method(os, "hostname", () => "oddly.named.host");
  const { apm } = setup(t);
  assert.equal(apm.deployment, "oddly.named.host");
});

test("outside Kubernetes the payload has no kubernetes key", async (t) => {
  k8sEnv(t);
  const { apm, sent } = setup(t);
  assert.equal(apm.deployment, null);
  assert.equal(apm.namespace, null);
  apm.counter("jobs").add();
  await apm.flush();
  assert.ok(!("kubernetes" in sent[0]));
});

test("kubernetes names are truncated at 253 chars", async (t) => {
  k8sEnv(t);
  const { apm } = setup(t, { deployment: "d".repeat(300), namespace: "n".repeat(300) });
  assert.equal(apm.deployment, "d".repeat(253));
  assert.equal(apm.namespace, "n".repeat(253));
});

// ---------------------------------------------------------------------------
// fetch + database instrumentation

test("sqlSpanName extracts operation and table, never the payload", () => {
  const { sqlSpanName } = mod._internals;
  assert.equal(sqlSpanName("SELECT * FROM users WHERE id = 1"), "SELECT users");
  assert.equal(sqlSpanName("insert into orders values (1)"), "INSERT orders");
  assert.equal(sqlSpanName("UPDATE public.accounts SET x=1"), "UPDATE public.accounts");
  assert.equal(sqlSpanName("BEGIN"), "BEGIN");
  assert.equal(sqlSpanName(""), "SQL");
  assert.equal(sqlSpanName(null), "SQL");
});

test("global fetch records metrics, a span, and delivers a traceparent", async (t) => {
  const { apm } = setup(t, { httpInstrumentation: true });
  const before = globalThis.fetch;
  mod._internals.instrumentFetch(); // idempotent: no double patch
  assert.equal(globalThis.fetch, before);

  const received = [];
  const { port } = await startServer(t, (req, res) => {
    received.push({ ...req.headers });
    res.end("ok");
  });
  const destination = `127.0.0.1:${port}`;

  let traceId;
  await apm.transaction("GET /via-fetch", async (tx) => {
    traceId = tx.traceId;
    const res = await fetch(`http://${destination}/data`);
    assert.equal(await res.text(), "ok");
  });

  const [headers] = received;
  assert.match(headers.traceparent, new RegExp(`^00-${traceId}-[0-9a-f]{16}-01$`));

  const tags = `destination=${destination},status=2xx`;
  assert.equal(apm._buffer.get(key("http.client.duration", tags)).count, 1);
  assert.equal(apm._buffer.get(key("http.client.requests", tags)).count, 1);
  const [sample] = apm._traceSamples;
  const [span] = sample.spans;
  assert.equal(span.name, `GET ${destination}`);
  assert.equal(span.type, "http");
});

test("suppressed calls keep metrics but add no span", async (t) => {
  const { apm } = setup(t, { httpInstrumentation: true });
  const { port } = await startServer(t, (req, res) => res.end("ok"));

  await apm.transaction("GET /suppressed", async () => {
    await mod._internals.suppressedSpans.run(true, async () => {
      await get(`http://127.0.0.1:${port}/data`);
    });
  });

  const tags = `destination=127.0.0.1:${port},status=2xx`;
  assert.equal(apm._buffer.get(key("http.client.requests", tags)).count, 1);
  const [sample] = apm._traceSamples;
  assert.deepEqual(sample.spans, []);
});

test("mongodb operations become db spans (needs local mongod)", async (t) => {
  let mongodb;
  try {
    mongodb = require("mongodb");
  } catch {
    t.skip("mongodb driver not installed");
    return;
  }
  const client = new mongodb.MongoClient("mongodb://127.0.0.1:27099", {
    serverSelectionTimeoutMS: 1500,
  });
  try {
    await client.connect();
  } catch {
    t.skip("no mongod on 127.0.0.1:27099");
    return;
  }
  t.after(() => client.close());

  const { apm } = setup(t, {}); // dbInstrumentation defaults on

  await apm.transaction("GET /mongo", async () => {
    const col = client.db("apmtest").collection("things");
    await col.insertOne({ n: 1 });
    await col.find({ n: 1 }).toArray();
    await col.deleteMany({});
  });

  const [sample] = apm._traceSamples;
  const spans = sample.spans.map((s) => [s.name, s.type, s.subtype]);
  assert.deepEqual(spans, [
    ["insertOne apmtest.things", "db", "mongodb"],
    ["find apmtest.things", "db", "mongodb"],
    ["deleteMany apmtest.things", "db", "mongodb"],
  ]);
  const group = apm._txBuffer.get(txKey("GET /mongo"));
  assert.equal(group.spans.get(spanKey("db", "mongodb")).count, 3);
});

// --- Continuous profiling ---------------------------------------------------
//
// The parts worth testing are the ones that run inside a customer's process
// with no supervision: the clamp that bounds what the server can ask for, and
// the conversion from V8's node graph into stacks.

const {
  CpuProfiler,
  clampProfileSettings,
  profileFrameName,
  PROFILE_BOUNDS,
} = mod._internals;

test("profiling stays off until the server turns it on", () => {
  assert.equal(clampProfileSettings(null).profiling_enabled, false);
  assert.equal(clampProfileSettings({}).profiling_enabled, false);
});

test("a ten kilohertz sample rate comes back bounded", () => {
  // The SDK clamps independently of the server, so a compromised or spoofed
  // control plane cannot spin a sampling loop inside every customer process.
  assert.equal(clampProfileSettings({ sample_rate_hz: 10000 }).sample_rate_hz, 200);
  assert.equal(clampProfileSettings({ sample_rate_hz: 0 }).sample_rate_hz, 10);
});

test("a non-numeric setting falls back to the default rather than NaN", () => {
  const resolved = clampProfileSettings({ sample_rate_hz: "fast" });
  assert.equal(resolved.sample_rate_hz, 100);
});

test("every published bound is enforced", () => {
  const wild = {};
  for (const key of Object.keys(PROFILE_BOUNDS)) wild[key] = 1e9;
  const resolved = clampProfileSettings(wild);
  for (const key of Object.keys(PROFILE_BOUNDS)) {
    const [low, high] = PROFILE_BOUNDS[key];
    assert.ok(resolved[key] >= low && resolved[key] <= high, key);
  }
});

test("a frame is named by module and function, without a line number", () => {
  // A line number would give a function a new identity every time an edit
  // shifted it down, which would break diffing across a deploy.
  assert.equal(
    profileFrameName({ functionName: "handle", url: "file:///app/routes/checkout.js", lineNumber: 42 }),
    "checkout.handle"
  );
  assert.equal(profileFrameName({ functionName: "", url: "file:///app/a.js" }), "a.(anonymous)");
  assert.equal(profileFrameName({ functionName: "(garbage collector)", url: "" }), "(garbage collector)");
});

// A V8 profile shaped exactly as Profiler.stop returns one:
//   (root) -> handler -> encode   sampled twice at 10ms
//   (root) -> handler             sampled once at 10ms
//   (idle)                        sampled once at 50ms
const V8_PROFILE = {
  nodes: [
    { id: 1, callFrame: { functionName: "(root)", url: "" }, children: [2, 5] },
    { id: 2, callFrame: { functionName: "handler", url: "file:///app/server.js" }, children: [3] },
    { id: 3, callFrame: { functionName: "encode", url: "file:///app/json.js" }, children: [] },
    { id: 5, callFrame: { functionName: "(idle)", url: "" }, children: [] },
  ],
  samples: [3, 3, 2, 5],
  timeDeltas: [10000, 10000, 10000, 50000], // microseconds
};

test("V8 samples convert into root-first stacks weighted by measured time", () => {
  const profiler = new CpuProfiler(clampProfileSettings({ sample_rate_hz: 100 }));
  const stacks = profiler._toStacks(V8_PROFILE);
  const byLeaf = new Map(stacks.map((s) => [s.frames[s.frames.length - 1], s]));

  assert.deepEqual(byLeaf.get("json.encode").frames, ["(root)", "server.handler", "json.encode"]);
  // Two samples of 10ms each, in nanoseconds -- from timeDeltas, not hitCount.
  assert.equal(byLeaf.get("json.encode").value, 20_000_000);
  assert.equal(byLeaf.get("server.handler").value, 10_000_000);
});

test("idle time is excluded from a CPU profile", () => {
  // Counting the event loop waiting as CPU would put every idle process at
  // 100% and make the vCPU-hour figure nonsense.
  const profiler = new CpuProfiler(clampProfileSettings({ sample_rate_hz: 100 }));
  const stacks = profiler._toStacks(V8_PROFILE);
  assert.ok(!stacks.some((s) => s.frames.some((f) => f.includes("idle"))));
  const total = stacks.reduce((sum, s) => sum + s.value, 0);
  assert.equal(total, 30_000_000); // the 50ms idle sample is not in it
});

test("stacks are capped without dropping the profile", () => {
  const profiler = new CpuProfiler({ ...clampProfileSettings({}), max_stacks: 1 });
  const stacks = profiler._toStacks(V8_PROFILE);
  assert.equal(stacks.length, 1);
});

test("a profile with no samples converts to nothing rather than throwing", () => {
  const profiler = new CpuProfiler(clampProfileSettings({}));
  assert.deepEqual(profiler._toStacks({ nodes: [], samples: [], timeDeltas: [] }), []);
  assert.deepEqual(profiler._toStacks({}), []);
});

test("the real V8 profiler attributes a hot function to its own frame", async () => {
  // The end-to-end claim: turn it on, burn CPU, and the burning function is
  // the one named.
  const profiler = new CpuProfiler(clampProfileSettings({ sample_rate_hz: 200 }));
  profiler.start();
  try {
    (function spinTheCpu() {
      let x = 0;
      const until = Date.now() + 250;
      while (Date.now() < until) x = (x * 31 + 7) % 1000003;
      return x;
    })();
    const profile = await profiler.drain();
    assert.equal(profile.profile_type, "cpu");
    const hottest = profile.stacks.sort((a, b) => b.value - a.value)[0];
    assert.ok(
      hottest.frames.some((f) => f.endsWith(".spinTheCpu")),
      `expected spinTheCpu in ${hottest.frames.join(" -> ")}`
    );
  } finally {
    profiler.stop();
  }
});

test("the first config poll runs however young the process is", async (t) => {
  // performance.now() starts near zero at process start. An initial 0 on the
  // "has the interval elapsed" guard would read as not-yet-due and skip the
  // very first fetch for a minute -- the Python SDK shipped exactly that bug,
  // where time.monotonic() is uptime and a fresh container reads single digits.
  const { apm } = setup(t);
  let calls = 0;
  apm._get = async () => {
    calls += 1;
    return { profiling_enabled: false, sample_rate_hz: 100 };
  };
  await apm._refreshProfileConfig();
  assert.equal(calls, 1);
  assert.ok(apm._profileConfig, "the fetched config was applied");
});

test("a second poll inside the interval is skipped", async (t) => {
  // The guard still has to throttle, or every flush would open a connection to
  // the control plane.
  const { apm } = setup(t);
  let calls = 0;
  apm._get = async () => {
    calls += 1;
    return { profiling_enabled: false };
  };
  await apm._refreshProfileConfig();
  await apm._refreshProfileConfig();
  assert.equal(calls, 1);
});

test("a profile is not uploaded before its interval elapses", async (t) => {
  // upload_interval_seconds is a control in the RootTrace UI, and the metric
  // flush cadence is a different number entirely -- 30s by default, settable
  // to 5. Uploading per metric flush would cut a 60s profile into slivers and
  // make the setting a lie.
  const { apm } = setup(t);
  let drained = 0;
  apm._profiler = {
    drain: async () => {
      drained += 1;
      return null;
    },
    stop() {},
  };
  apm._profileConfig = { upload_interval_seconds: 60 };
  apm._profileUploadAt = performance.now();
  await apm._flushProfile();
  assert.equal(drained, 0);

  // Pretend the window has passed rather than sleeping through it.
  apm._profileUploadAt -= 60_000;
  await apm._flushProfile();
  assert.equal(drained, 1);
});

test("the upload window is the server's number, not the flush cadence", async (t) => {
  const { apm } = setup(t);
  let drained = 0;
  apm._profiler = {
    drain: async () => {
      drained += 1;
      return null;
    },
    stop() {},
  };
  apm._profileConfig = { upload_interval_seconds: 300 };
  apm._profileUploadAt = performance.now() - 30_000; // a whole metric interval
  await apm._flushProfile();
  assert.equal(drained, 0);
});

test("the poll interval is measured on a monotonic clock", async (t) => {
  // Date.now() would stall polling for the length of any backwards NTP step --
  // routine on a VM that boots with a bad clock and then syncs.
  const { apm } = setup(t);
  apm._get = async () => ({ profiling_enabled: false });
  await apm._refreshProfileConfig();
  // performance.now() is milliseconds since process start, so a stamp taken
  // just now is small. An epoch-millisecond stamp would be ~1.7e12.
  assert.ok(
    apm._profileConfigAt < 1e9,
    `expected a monotonic stamp, got ${apm._profileConfigAt}`
  );
});

// --- Security sinks ---------------------------------------------------------

const { reportSink, instrumentSecuritySinks, securityEvents } = mod._internals;

test("spawning a process is reported, without its arguments", () => {
  instrumentSecuritySinks();
  securityEvents.length = 0;
  const childProcess = require("node:child_process");
  childProcess.execSync("/bin/echo s3cret-token-value");
  assert.ok(securityEvents.length >= 1);
  assert.equal(securityEvents[0].kind, "process_spawn");
  assert.equal(securityEvents[0].target, "/bin/echo");
  // argv is the payload; the executable is the behaviour.
  assert.ok(!JSON.stringify(securityEvents).includes("s3cret-token-value"));
  securityEvents.length = 0;
});

test("the wrapped call still returns what it used to", () => {
  instrumentSecuritySinks();
  securityEvents.length = 0;
  const childProcess = require("node:child_process");
  assert.equal(childProcess.execSync("/bin/echo ok").toString().trim(), "ok");
  securityEvents.length = 0;
});

test("the buffer cannot grow without bound", () => {
  // A process being driven by an attacker outruns any flush interval.
  securityEvents.length = 0;
  for (let i = 0; i < 400; i += 1) reportSink("process_spawn", "/bin/sh");
  assert.equal(securityEvents.length, 100);
  securityEvents.length = 0;
});

test("reporting never throws into the application", () => {
  securityEvents.length = 0;
  const hostile = { toString() { throw new Error("nope"); } };
  assert.doesNotThrow(() => reportSink("process_spawn", hostile));
  securityEvents.length = 0;
});
