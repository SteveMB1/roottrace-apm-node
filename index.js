"use strict";

// RootTrace APM wrapper for Node.js.
//
// Aggregates counters, gauges, and timers in memory and posts one ingest
// payload per flush interval to the RootTrace API; buffered structured
// logs ship as a second request on the same interval. Core modules only.

const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { AsyncLocalStorage } = require("node:async_hooks");
const { performance, monitorEventLoopDelay, PerformanceObserver } = require("node:perf_hooks");

const VERSION = "0.4.3";
const DEFAULT_API_URL = "https://api.roottrace.io/api";
const MAX_ENTRIES = 500; // wire cap per ingest request
const MAX_USER_ENTRIES = MAX_ENTRIES - 8; // headroom so runtime metrics fit under the cap
const MAX_TAG_KEYS = 8;
const MAX_NAME_LENGTH = 200;
const MAX_TX_GROUPS = 250; // transaction groups per flush (PROTOCOL.md)
const MAX_TX_BREAKDOWN_ROWS = 40; // span-breakdown rows per transaction group
const MAX_TX_TYPE_LENGTH = 40;
const MAX_SUBTYPE_LENGTH = 200;
const MAX_ERRORS = 50; // distinct error fingerprints per flush
const MAX_MESSAGE_LENGTH = 1000;
const MAX_CULPRIT_LENGTH = 300;
const MAX_STACK_FRAMES = 50;
const MAX_ERROR_TYPE_LENGTH = 200;
const MAX_FRAME_FUNCTION_LENGTH = 300;
const MAX_FRAME_FILE_LENGTH = 1024;
const MAX_SERVICE_LENGTH = 160;
const MAX_SERVICE_VERSION_LENGTH = 64;
const MAX_K8S_NAME_LENGTH = 253; // DNS-1123 cap on Kubernetes names (PROTOCOL.md)
const K8S_NAMESPACE_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
const RESERVED_METRIC_NAME = "errors.count"; // the server folds error rollups into this name
const MAX_TRACE_SAMPLES = 2; // slowest transactions kept per flush
const MAX_SAMPLE_SPANS = 100; // spans kept on one trace sample
const MAX_HTTP_PATH_LENGTH = 1024; // http context on trace samples (PROTOCOL.md)
const MAX_HTTP_USER_AGENT_LENGTH = 300;
const MAX_HTTP_IP_LENGTH = 64; // fits IPv6 with a zone id
const MAX_LOG_ENTRIES = 500; // buffered log entries between flushes
const MAX_LOG_MESSAGE_LENGTH = 8 * 1024; // log messages truncate here
const LOG_LEVELS = new Set(["debug", "info", "warn", "error"]);

// --- Continuous profiling ---------------------------------------------------
//
// Off unless the server says otherwise. Profiling runs inside a customer's
// process, so the switch lives in the RootTrace UI where somebody can reach it
// during the incident it is causing -- not in an environment variable that
// needs a redeploy to change.
const PROFILE_CONFIG_INTERVAL_SECONDS = 60; // how often to re-ask what to do

// --- Security sinks --------------------------------------------------------
// Call sites an attacker needs and ordinary request handling rarely reaches.
// The fact is reported; the arguments never are, because an attacker's argv is
// the payload.
const SECURITY_MAX_EVENTS = 100;
const SECURITY_MAX_TARGET = 512;
const securityEvents = [];

function reportSink(kind, target) {
  // Runs inside somebody's request handler: never throws, never blocks, never
  // touches the network. The flush loop ships what it leaves behind.
  try {
    const tx = currentTransaction();
    const http = (tx && tx.http) || {};
    if (securityEvents.length >= SECURITY_MAX_EVENTS) return;
    securityEvents.push({
      kind,
      target: String(target).slice(0, SECURITY_MAX_TARGET),
      observed_at: new Date().toISOString(),
      trace_id: tx ? tx.traceId : null,
      transaction: tx ? tx.name : null,
      method: http.method || null,
      path: http.path || null,
    });
  } catch {
    // A detector that breaks the application it watches is worse than none.
  }
}

let securityPatched = false;

function instrumentSecuritySinks() {
  if (securityPatched) return;
  securityPatched = true;
  try {
    const childProcess = require("node:child_process");
    for (const name of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync"]) {
      const original = childProcess[name];
      if (typeof original !== "function") continue;
      childProcess[name] = function (command, ...rest) {
        // The executable only. Everything after it is the payload.
        try {
          const target = Array.isArray(command) ? command[0] : String(command).split(" ")[0];
          reportSink("process_spawn", target || "?");
        } catch {
          // ignored: reporting must not change what the app was about to do
        }
        return original.call(this, command, ...rest);
      };
    }
  } catch (err) {
    log(`could not instrument process spawning: ${err.message}`);
  }
}
const PROFILE_MAX_FRAMES = 128;
const PROFILE_MAX_STACKS = 5000; // distinct stacks kept per upload
// Every bound the server enforces, enforced here again. Trusting the server to
// bound this would turn a compromised or spoofed control plane into an
// application-level DoS inside every process running the SDK. It costs four
// lines, so there is no argument for leaving it out.
const PROFILE_BOUNDS = {
  sample_rate_hz: [10, 200],
  upload_interval_seconds: [15, 900],
  max_frames: [16, PROFILE_MAX_FRAMES],
  max_stacks: [500, PROFILE_MAX_STACKS],
};
const PROFILE_DEFAULTS = {
  sample_rate_hz: 100,
  upload_interval_seconds: 60,
  max_frames: PROFILE_MAX_FRAMES,
  max_stacks: PROFILE_MAX_STACKS,
};

// Marks the wrapper's own flush requests so the http instrumentation
// never measures them.
const kSelfRequest = Symbol("roottrace-apm-self-request");

// The active transaction, isolated per async execution context so spans
// and outbound calls attach to the right transaction across awaits.
const activeTransaction = new AsyncLocalStorage();

function log(msg) {
  console.error("roottrace-apm: " + msg);
}

function currentTransaction() {
  const tx = activeTransaction.getStore();
  if (!tx || tx.closed) return null; // a closed transaction is treated as absent
  return tx;
}

// W3C traceparent: 2-hex version, 32-hex trace id, 16-hex parent id, 2-hex
// flags. Future versions (anything but ff) may append "-suffix" fields.
const TRACEPARENT_RE = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}(-.*)?$/i;

function parseTraceparent(value) {
  if (typeof value !== "string") return null;
  const match = TRACEPARENT_RE.exec(value.trim());
  if (!match) return null;
  const version = match[1].toLowerCase();
  if (version === "ff") return null; // forbidden per W3C
  if (version === "00" && match[4]) return null; // version 00 has exactly four fields
  const traceId = match[2].toLowerCase();
  if (traceId === "0".repeat(32) || match[3].toLowerCase() === "0".repeat(16)) return null;
  return traceId;
}

function tagsKey(tags) {
  // Canonical k=v,k=v form (PROTOCOL.md): percent-encode %, =, and , in
  // keys and values so distinct tag maps never collide. '%' goes first.
  const esc = (s) => s.replace(/%/g, "%25").replace(/=/g, "%3D").replace(/,/g, "%2C");
  return Object.keys(tags)
    .sort()
    .map((k) => `${esc(k)}=${esc(String(tags[k]))}`)
    .join(",");
}

function env(name, fallback = "") {
  const value = process.env[name];
  return value === undefined ? fallback : value.trim();
}

function toFiniteNumber(value) {
  // Strict-ish coercion: null, booleans, and objects are not measurements.
  if (typeof value === "number") return value;
  if (typeof value === "string" && value.trim() !== "") return Number(value);
  return NaN;
}

let sumOverflowWarned = false;

// Adds delta to a running sum, keeping the previous value if the result
// would overflow: JSON.stringify serializes Infinity as null, which the
// server would fold into a corrupted rollup instead of rejecting.
function addFinite(sum, delta) {
  const next = sum + delta;
  if (Number.isFinite(next)) return next;
  if (!sumOverflowWarned) {
    sumOverflowWarned = true;
    log("a metric sum would overflow; keeping the previous value");
  }
  return sum;
}

// Histogram bucket index for a duration in ms, per the contract shared by
// every wrapper and the server: log2 scale, four buckets per doubling,
// index 40 at 1ms, clamped to 0-127. On the wire buckets are an object of
// stringified integer index -> count.
function bucketIndex(d) {
  return Math.min(127, Math.max(0, Math.floor(Math.log2(Math.max(d, 0.001)) * 4) + 40));
}

function addToBucket(buckets, durationMs) {
  const idx = bucketIndex(durationMs);
  buckets[idx] = (buckets[idx] || 0) + 1;
}

function mergeBuckets(into, from) {
  if (!from) return; // a missing map merges as empty
  for (const idx of Object.keys(from)) into[idx] = (into[idx] || 0) + from[idx];
}

class HttpStatusError extends Error {
  constructor(code, detail, retryAfter) {
    super(`RootTrace API returned HTTP ${code}: ${detail}`);
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

class UnserializableError extends Error {} // JSON.stringify refused the payload

// Numeric, UUID-shaped, or long-hex (>=16 chars: Mongo ObjectIds, hashes)
// path segments become ":id" in transaction names.
const ID_SEGMENT_RE =
  /^(?:\d+|[0-9a-fA-F]{16,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$/;

function normalizePath(p) {
  if (!p) return "/";
  return (
    p
      .split("/")
      .map((segment) => (ID_SEGMENT_RE.test(segment) ? ":id" : segment))
      .join("/") || "/"
  );
}

// ---------------------------------------------------------------------------
// Kubernetes context

// Deployment pods look like <name>-<replicaset-hash>-<suffix>; StatefulSet
// pods look like <name>-<ordinal>. Names matching neither are sent as-is.
const K8S_DEPLOYMENT_POD_RE = /^(.+)-[a-z0-9]{5,10}-[a-z0-9]{5}$/;
const K8S_STATEFULSET_POD_RE = /^(.+)-\d+$/;

// Coerce, trim, and truncate one Kubernetes name; null when empty.
function sanitizeK8sName(value) {
  if (value === undefined || value === null) return null;
  const name = String(value).trim();
  if (!name) return null;
  if (name.length > MAX_K8S_NAME_LENGTH) {
    log(`kubernetes name longer than ${MAX_K8S_NAME_LENGTH} chars; truncating`);
    return name.slice(0, MAX_K8S_NAME_LENGTH);
  }
  return name;
}

function deploymentFromPod(pod) {
  const match = K8S_DEPLOYMENT_POD_RE.exec(pod) || K8S_STATEFULSET_POD_RE.exec(pod);
  return match ? match[1] : pod;
}

// Resolves the Kubernetes context once at init; null outside a cluster.
// Explicit values (init options, then the ROOTTRACE_APM_DEPLOYMENT /
// ROOTTRACE_APM_NAMESPACE env vars, resolved by init()) win; in-cluster
// auto-detection only fills the gaps, and only when KUBERNETES_SERVICE_HOST
// says the process runs inside a cluster. Never throws.
function detectKubernetes(hostname, explicitDeployment, explicitNamespace) {
  let deployment = sanitizeK8sName(explicitDeployment);
  let namespace = sanitizeK8sName(explicitNamespace);
  const inCluster = env("KUBERNETES_SERVICE_HOST") !== "";
  const pod = sanitizeK8sName(hostname);
  if (inCluster) {
    if (!deployment && pod) deployment = deploymentFromPod(pod);
    if (!namespace) {
      try {
        namespace = sanitizeK8sName(fs.readFileSync(K8S_NAMESPACE_FILE, "utf8"));
      } catch (err) {
        void err; // not readable; the namespace stays unknown
      }
    }
  }
  if (!inCluster && !deployment && !namespace) {
    return null; // the payload omits the kubernetes object entirely
  }
  const kubernetes = {};
  if (deployment) kubernetes.deployment = deployment;
  if (namespace) kubernetes.namespace = namespace;
  if (pod) kubernetes.pod = pod; // sent whenever the object is: it's the hostname
  return Object.keys(kubernetes).length ? kubernetes : null;
}

// ---------------------------------------------------------------------------
// Errors

function isAppFile(file) {
  if (!file || file.startsWith("node:") || file.includes("node_modules")) return false;
  return file !== __filename;
}

function parseStackFrames(stack) {
  // V8 format, innermost frame first: "    at fn (file:line:col)".
  const frames = [];
  if (typeof stack !== "string") return frames;
  for (const raw of stack.split("\n")) {
    const line = raw.trim();
    if (!line.startsWith("at ")) continue;
    let fn = "";
    let loc = line.slice(3);
    const open = loc.lastIndexOf(" (");
    if (open !== -1 && loc.endsWith(")")) {
      fn = loc.slice(0, open);
      loc = loc.slice(open + 2, -1);
    }
    const m = /^(.*):(\d+):\d+$/.exec(loc);
    frames.push({
      function: (fn || "<anonymous>").slice(0, MAX_FRAME_FUNCTION_LENGTH),
      file: (m ? m[1] : loc).slice(0, MAX_FRAME_FILE_LENGTH),
      line: m ? parseInt(m[2], 10) : 0,
    });
  }
  return frames;
}

function buildError(err) {
  const typeName = String(err.name || (err.constructor && err.constructor.name) || "Error")
    .slice(0, MAX_ERROR_TYPE_LENGTH);
  const message = String(err.message === undefined ? err : err.message).slice(0, MAX_MESSAGE_LENGTH);
  let frames = parseStackFrames(err.stack); // innermost first
  // Culprit: the deepest app frame; else the deepest frame of all.
  let culpritFrame = frames.find((f) => isAppFile(f.file)) || frames[0] || null;
  let culprit = "<unknown>";
  if (culpritFrame) {
    const mod = path.basename(culpritFrame.file).replace(/\.[cm]?js$/, "");
    culprit = mod ? `${mod}.${culpritFrame.function}` : culpritFrame.function;
  }
  culprit = culprit.slice(0, MAX_CULPRIT_LENGTH);
  // Keep the innermost frames when the stack is deep; outermost-first order.
  frames = frames.slice(0, MAX_STACK_FRAMES).reverse();
  const digest = crypto.createHash("sha256");
  digest.update(typeName);
  digest.update(culprit);
  for (const frame of frames.slice(-5)) {
    // the frames closest to the throw identify it
    digest.update(`${frame.file}:${frame.function}`);
  }
  return {
    fingerprint: digest.digest("hex").slice(0, 16),
    type: typeName,
    message,
    culprit,
    count: 1,
    stack: frames,
  };
}

// ---------------------------------------------------------------------------
// Transactions

class Span {
  constructor(tx, name, type, subtype) {
    this._tx = tx;
    this._name = name;
    this._type = type;
    this._subtype = subtype;
    this._start = performance.now();
    this._done = false;
  }

  end() {
    try {
      if (this._done) return;
      this._done = true;
      const tx = this._tx;
      if (!tx || tx.closed) return; // transaction gone: the span is a no-op
      tx._addSpan(
        this._name,
        this._type,
        this._subtype,
        this._start - tx._start,
        performance.now() - this._start
      );
    } catch (err) {
      log(`failed to finish span: ${err.message}`);
    }
  }
}

class Transaction {
  constructor(apm, name, type, traceId) {
    this._apm = apm;
    this.name = String(name).slice(0, MAX_NAME_LENGTH) || "unnamed";
    this.type = String(type).slice(0, MAX_TX_TYPE_LENGTH) || "request";
    this.traceId = traceId;
    this.startedAt = Date.now();
    this.spans = []; // kept for the trace sample, capped
    this.spansDropped = 0;
    this.closed = false; // set once recorded; late spans then no-op
    this.failed = false;
    this.http = null; // request context; rides the trace sample when set
    this.breakdown = new Map(); // "type\0subtype" -> {type, subtype, count, sum}
    this._start = performance.now();
  }

  _addSpan(name, type, subtype, startOffsetMs, durationMs) {
    name = String(name).slice(0, MAX_NAME_LENGTH) || "unnamed";
    type = String(type).slice(0, MAX_TX_TYPE_LENGTH) || "custom";
    subtype = subtype ? String(subtype).slice(0, MAX_SUBTYPE_LENGTH) : null;
    const key = `${type}\u0000${subtype || ""}`;
    let row = this.breakdown.get(key);
    if (!row) {
      row = { type, subtype, count: 0, sum: 0 };
      this.breakdown.set(key, row);
    }
    row.count += 1;
    row.sum = addFinite(row.sum, durationMs);
    if (this.spans.length >= MAX_SAMPLE_SPANS) {
      this.spansDropped += 1;
      return;
    }
    const span = { name, type };
    if (subtype) span.subtype = subtype;
    span.start_offset_ms = startOffsetMs;
    span.duration_ms = durationMs;
    this.spans.push(span);
  }

  startSpan(name, type = "custom", subtype = null) {
    return new Span(this.closed ? null : this, name, type, subtype);
  }

  setOutcome(outcome) {
    if (outcome === "failed") this.failed = true;
    else if (outcome === "success") this.failed = false;
  }

  setHttp(fields) {
    // Request details for this transaction. When it wins a trace-sample
    // slot they ship as the sample's "http" object (wire keys per
    // PROTOCOL.md), so the dashboard can show where a slow or failing
    // request came from. Missing fields stay unset; values are clipped.
    try {
      if (!fields || typeof fields !== "object") return;
      const http = this.http || (this.http = {});
      const strings = [
        ["method", fields.method, MAX_TX_TYPE_LENGTH],
        ["path", fields.path, MAX_HTTP_PATH_LENGTH],
        ["client_ip", fields.clientIp, MAX_HTTP_IP_LENGTH],
        ["remote_ip", fields.remoteIp, MAX_HTTP_IP_LENGTH],
        ["user_agent", fields.userAgent, MAX_HTTP_USER_AGENT_LENGTH],
      ];
      for (const [key, value, cap] of strings) {
        if (value !== undefined && value !== null) http[key] = String(value).slice(0, cap);
      }
      if (fields.statusCode !== undefined && fields.statusCode !== null) {
        const status = Number(fields.statusCode);
        // The server rejects codes outside 0-999 — and a rejected payload
        // takes the whole flush down with it.
        if (Number.isInteger(status) && status >= 0 && status <= 999) {
          http.status_code = status;
        } else {
          this._apm._warnThrottled(
            "http-status-code",
            `ignoring invalid statusCode ${fields.statusCode} on transaction "${this.name}"`
          );
        }
      }
    } catch (err) {
      log(`failed to set http context: ${err.message}`);
    }
  }

  captureException(err) {
    this._apm._captureError(err, this.name);
  }

  end() {
    try {
      if (this.closed) return;
      this.closed = true;
      const outcome = this.failed ? "failed" : "success";
      this._apm._recordTransaction(this, performance.now() - this._start, outcome);
    } catch (err) {
      log(`failed to finish transaction: ${err.message}`);
    }
  }
}

// ---------------------------------------------------------------------------
// The Apm instance

function clampProfileSettings(raw) {
  // Force a server-supplied profiling config into ranges this SDK accepts.
  // Independent of the server's own clamping, on purpose. See PROFILE_BOUNDS.
  const config = raw || {};
  const result = { profiling_enabled: Boolean(config.profiling_enabled) };
  for (const key of Object.keys(PROFILE_BOUNDS)) {
    const [low, high] = PROFILE_BOUNDS[key];
    let value = Number.parseInt(config[key], 10);
    if (!Number.isFinite(value)) value = PROFILE_DEFAULTS[key];
    result[key] = Math.max(low, Math.min(high, value));
  }
  return result;
}

function profileFrameName(callFrame) {
  // Module and function, deliberately without a line number: a line number
  // would give a function a new identity every time an edit shifted it down,
  // which would break diffing a flamegraph across a deploy -- the one thing
  // this is for.
  const fn = callFrame.functionName || "(anonymous)";
  const url = callFrame.url || "";
  if (!url) return fn; // V8's own pseudo-frames: (program), (garbage collector)
  let file = url.split("/").pop() || url;
  file = file.replace(/\?.*$/, "").replace(/\.(js|mjs|cjs|ts)$/, "");
  return `${file}.${fn}`;
}

class CpuProfiler {
  // V8's own CPU profiler, over node:inspector. Built into Node, so no native
  // dependency and nothing to compile -- which is what lets this install in an
  // air-gapped environment like everything else RootTrace ships.
  //
  // Unlike the Python SDK's wall-clock sampler, this really is CPU time: V8
  // samples the running JavaScript stack, so a request blocked on a socket
  // costs nothing here. The two are never merged; profile_type keeps them
  // apart all the way to the UI.
  constructor(settings) {
    this._settings = settings;
    this._session = null;
    this._startedAt = 0;
    this._overheadMs = 0;
  }

  start() {
    // Required lazily: a Node built without the inspector, or a worker thread
    // that cannot open a session, must degrade to no profiling rather than
    // taking the process down on require.
    const inspector = require("node:inspector");
    this._session = new inspector.Session();
    this._session.connect();
    this._post("Profiler.enable");
    this._post("Profiler.setSamplingInterval", {
      interval: Math.round(1e6 / this._settings.sample_rate_hz), // microseconds
    });
    this._post("Profiler.start");
    this._startedAt = performance.now();
  }

  stop() {
    if (!this._session) return;
    // Disconnecting stops the profiler; the in-flight profile is deliberately
    // discarded, since stop() is only reached on shutdown or a settings change.
    try {
      this._session.disconnect();
    } catch (err) {
      log(`stopping the CPU profiler failed: ${err.message}`);
    }
    this._session = null;
  }

  _post(method, params) {
    return new Promise((resolve, reject) => {
      this._session.post(method, params, (err, result) =>
        err ? reject(err) : resolve(result)
      );
    });
  }

  async drain() {
    // Stop, convert, restart. A profile per flush window.
    if (!this._session) return null;
    const began = performance.now();
    let profile;
    try {
      ({ profile } = await this._post("Profiler.stop"));
      await this._post("Profiler.start");
    } catch (err) {
      log(`CPU profile collection failed: ${err.message}`);
      return null;
    }
    const elapsedMs = began - this._startedAt;
    this._startedAt = performance.now();
    const stacks = this._toStacks(profile);
    this._overheadMs += performance.now() - began;
    const overhead = this._overheadMs;
    this._overheadMs = 0;
    if (!stacks.length) return null;
    return {
      profile_type: "cpu",
      value_unit: "nanoseconds",
      period_ms: 1000 / this._settings.sample_rate_hz,
      duration_ms: elapsedMs,
      sample_count: (profile.samples || []).length,
      stacks,
      // Measured, not asserted -- but measuring exactly what it says. This is
      // the SDK's own collection and conversion cost, once per upload window.
      // V8's in-process sampling is not observable from JavaScript, so it is
      // NOT included here; the docs say so rather than letting this number be
      // read as the total. The Python SDK's equivalent figure does include its
      // sampling, because there the sampler is a thread we own.
      overhead_percent: elapsedMs > 0 ? Number(((100 * overhead) / elapsedMs).toFixed(3)) : 0,
    };
  }

  _toStacks(profile) {
    const nodes = profile.nodes || [];
    const byId = new Map();
    const parentOf = new Map();
    for (const node of nodes) {
      byId.set(node.id, node);
      for (const childId of node.children || []) parentOf.set(childId, node.id);
    }

    // Attribute each sample the time until the next one, rather than using
    // hitCount. hitCount assumes every sample cost exactly one nominal
    // interval; timeDeltas are what V8 actually measured, so a stall shows up
    // as the stall it was instead of being averaged away.
    const nanosByNode = new Map();
    const samples = profile.samples || [];
    const deltas = profile.timeDeltas || [];
    for (let i = 0; i < samples.length; i += 1) {
      const micros = deltas[i];
      if (!Number.isFinite(micros) || micros <= 0) continue;
      const id = samples[i];
      nanosByNode.set(id, (nanosByNode.get(id) || 0) + micros * 1000);
    }

    const maxFrames = this._settings.max_frames;
    const merged = new Map(); // "ab" -> {frames, value}
    let dropped = 0;
    for (const [nodeId, nanos] of nanosByNode) {
      const frames = [];
      let current = nodeId;
      let idle = false;
      while (current !== undefined && frames.length < maxFrames) {
        const node = byId.get(current);
        if (!node) break;
        const name = profileFrameName(node.callFrame || {});
        // (idle) is the event loop with nothing to run. Counting it as CPU
        // would put every idle process at 100% and make the vCPU-hour figure
        // -- the whole reason this profile exists -- nonsense.
        if (name === "(idle)") { idle = true; break; }
        frames.push(name);
        current = parentOf.get(current);
      }
      if (idle || !frames.length) continue;
      frames.reverse(); // parent walk is leaf-to-root; graphs are drawn root-first
      // A separator no frame name can contain, so ("ab","c") and
      // ("a","bc") stay different stacks.
      const key = frames.join("\u001f");
      const existing = merged.get(key);
      if (existing) {
        existing.value += nanos;
      } else if (merged.size < this._settings.max_stacks) {
        merged.set(key, { frames, value: nanos });
      } else {
        dropped += 1;
      }
    }
    if (dropped) {
      log(`profiler dropped ${dropped} stacks: more than ${this._settings.max_stacks} distinct`);
    }
    return Array.from(merged.values());
  }
}

class Apm {
  constructor(opts) {
    this.service = opts.service;
    this.token = opts.token;
    this._apiUrl = opts.apiUrl.replace(/\/+$/, "");
    this.intervalSeconds = opts.intervalSeconds;
    this.serviceVersion = opts.serviceVersion || null;
    this.runtimeMetrics = opts.runtimeMetrics;
    this.hostname = os.hostname();
    this._kubernetes = detectKubernetes(this.hostname, opts.deployment, opts.namespace);
    this.tags = {};
    const rawTags = opts.tags || {};
    for (const k of Object.keys(rawTags)) this.tags[String(k)] = String(rawTags[k]);
    const tagNames = Object.keys(this.tags);
    if (tagNames.length > MAX_TAG_KEYS) {
      // trimmed once here: runtime metrics bypass the per-record trim
      log(`instance tags have ${tagNames.length} keys; keeping the first ${MAX_TAG_KEYS} in sorted order`);
      const kept = {};
      for (const k of tagNames.sort().slice(0, MAX_TAG_KEYS)) kept[k] = this.tags[k];
      this.tags = kept;
    }

    this._buffer = new Map(); // "name\0tagsKey" -> metric entry
    this._txBuffer = new Map(); // "name\0type" -> transaction group
    this._errorBuffer = new Map(); // fingerprint -> error entry
    this._traceSamples = []; // up to MAX_TRACE_SAMPLES, slowest win
    this._logBuffer = []; // structured log entries, oldest first, capped
    this._warned = new Set();
    this._retryAt = 0; // epoch-ms deadline set by HTTP 429 Retry-After
    this._flushChain = Promise.resolve();
    this._interval = null;
    this._started = performance.now();
    this._cpuSample = { usage: process.cpuUsage(), wall: this._started };
    this._gcCollections = 0;
    this._gcTimeMs = 0;
    this._eventLoopDelay = null;
    this._gcObserver = null;
    this._profiler = null; // set only once the server says profiling is on
    this._profileConfig = null;
    // -Infinity, and a monotonic clock. Two separate hazards:
    //   * performance.now() starts near zero at process start, so an initial 0
    //     would make the guard read "interval not elapsed" and skip the very
    //     first config fetch for a minute.
    //   * Date.now() is wall clock, so an NTP step backwards -- routine on a VM
    //     that boots with a bad clock and then syncs -- would stall polling
    //     until wall time caught up again.
    this._profileConfigAt = -Infinity;
    this._profileUploadAt = 0;
    if (this.runtimeMetrics) {
      try {
        this._eventLoopDelay = monitorEventLoopDelay({ resolution: 20 });
        this._eventLoopDelay.enable();
        this._gcObserver = new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            this._gcCollections += 1;
            this._gcTimeMs += entry.duration;
          }
        });
        this._gcObserver.observe({ entryTypes: ["gc"] });
      } catch (err) {
        log(`runtime metric monitors unavailable: ${err.message}`);
      }
    }
  }

  get apiUrl() {
    return this._apiUrl;
  }

  get ingestUrl() {
    return this._apiUrl + "/apm/ingest";
  }

  get logsUrl() {
    return this._apiUrl + "/logs/ingest";
  }

  get profilesUrl() {
    return this._apiUrl + "/apm/profiles";
  }

  get securityUrl() {
    return this._apiUrl + "/apm/security-events";
  }

  get configUrl() {
    return this._apiUrl + "/apm/config?service=" + encodeURIComponent(this.service);
  }

  get profiling() {
    // True while the CPU profiler is running. Read-only; the server decides.
    return this._profiler !== null;
  }

  get deployment() {
    // The resolved Kubernetes deployment name, or null. Read-only.
    return (this._kubernetes && this._kubernetes.deployment) || null;
  }

  get namespace() {
    // The resolved Kubernetes namespace, or null. Read-only.
    return (this._kubernetes && this._kubernetes.namespace) || null;
  }

  _start() {
    // unref() so the flush loop never keeps the process alive on its own.
    this._interval = setInterval(() => {
      // Config first, so a profile that was just switched on in the UI starts
      // before this tick's upload rather than after it. Deliberately not
      // inside flush(): a caller asking to flush wants its buffered metrics
      // sent, not a second connection opened to the control plane.
      this._flushChain = this._flushChain
        .then(() => this._refreshProfileConfig())
        .catch((err) => log(`profiling config refresh failed: ${err.message}`));
      this.flush();
    }, this.intervalSeconds * 1000);
    this._interval.unref();
  }

  _warnThrottled(key, msg) {
    // At most one warning per key per flush interval; flush clears the set.
    if (this._warned.has(key)) return;
    this._warned.add(key);
    log(msg);
  }

  // -- instruments ----------------------------------------------------------

  counter(name, tags = null, unit = null) {
    return { add: (amount = 1) => this._record(name, "counter", tags, unit, amount) };
  }

  gauge(name, tags = null, unit = null) {
    return { set: (value) => this._record(name, "gauge", tags, unit, value) };
  }

  timer(name, tags = null, unit = "ms") {
    const record = (ms) => this._record(name, "timer", tags, unit, ms);
    return {
      record,
      time: (fn) => {
        const start = performance.now();
        const finish = () => record(performance.now() - start);
        let result;
        try {
          result = fn();
        } catch (err) {
          finish();
          throw err;
        }
        if (result && typeof result.then === "function") {
          return result.then(
            (value) => {
              finish();
              return value;
            },
            (err) => {
              finish();
              throw err;
            }
          );
        }
        finish();
        return result;
      },
    };
  }

  _record(name, kind, tags, unit, value) {
    // Guarded end to end: instrumentation must never throw into the app.
    try {
      value = toFiniteNumber(value);
      if (!Number.isFinite(value)) {
        // JSON.stringify would silently turn NaN into null; drop it here.
        this._warnThrottled(`non-finite:${name}`, `ignoring non-numeric value for ${kind} "${name}"`);
        return;
      }
      if (name === undefined || name === null || name === "") {
        this._warnThrottled("name-empty", `ignoring ${kind} recording with empty metric name`);
        return;
      }
      if (typeof name !== "string") name = String(name);
      if (unit !== null && unit !== undefined && typeof unit !== "string") unit = String(unit);
      if (name === RESERVED_METRIC_NAME) {
        this._warnThrottled(
          "name-reserved",
          `metric name "${name}" is reserved for server-side error rollups; dropping`
        );
        return;
      }
      if (name.length > MAX_NAME_LENGTH) {
        this._warnThrottled(
          `name-length:${name.slice(0, MAX_NAME_LENGTH)}`,
          `metric name longer than ${MAX_NAME_LENGTH} chars; truncating`
        );
        name = name.slice(0, MAX_NAME_LENGTH);
      }
      let merged = { ...this.tags };
      for (const k of Object.keys(tags || {})) merged[String(k)] = String(tags[k]);
      const mergedKeys = Object.keys(merged);
      if (mergedKeys.length > MAX_TAG_KEYS) {
        this._warnThrottled(
          `tag-keys:${name}`,
          `metric "${name}" has ${mergedKeys.length} tag keys; keeping the first ${MAX_TAG_KEYS} in sorted order`
        );
        const kept = {};
        for (const k of mergedKeys.sort().slice(0, MAX_TAG_KEYS)) kept[k] = merged[k];
        merged = kept;
      }
      const key = `${name}\u0000${tagsKey(merged)}`;
      let entry = this._buffer.get(key);
      if (!entry) {
        if (this._buffer.size >= MAX_USER_ENTRIES) {
          this._warnThrottled(
            "entry-cap",
            `metric buffer full at ${MAX_USER_ENTRIES} entries; dropping new series until next flush`
          );
          return;
        }
        entry = { name, kind, unit: unit || null, tags: merged };
        if (kind === "counter") {
          entry.count = 0;
          entry.sum = 0;
        } else if (kind === "timer") {
          entry.count = 0;
          entry.sum = 0;
          entry.min = value;
          entry.max = value;
          entry.buckets = {};
        }
        this._buffer.set(key, entry);
      }
      if (entry.kind !== kind) {
        log(`metric "${name}" is a ${entry.kind}; ignoring ${kind} recording`);
        return;
      }
      if (kind === "counter") {
        entry.count += 1;
        entry.sum = addFinite(entry.sum, value);
      } else if (kind === "timer") {
        entry.count += 1;
        entry.sum = addFinite(entry.sum, value);
        entry.min = Math.min(entry.min, value);
        entry.max = Math.max(entry.max, value);
        addToBucket(entry.buckets, value);
      } else {
        entry.value = value;
      }
    } catch (err) {
      log(`failed to record metric: ${err.message}`);
    }
  }

  // -- transactions ---------------------------------------------------------

  startTransaction(name, opts = {}) {
    // Guarded: starting a transaction must never throw into the app.
    try {
      const traceId = parseTraceparent(opts.traceparent) || crypto.randomBytes(16).toString("hex");
      const tx = new Transaction(this, name, opts.type || "request", traceId);
      activeTransaction.enterWith(tx);
      return tx;
    } catch (err) {
      log(`failed to start transaction: ${err.message}`);
      return null;
    }
  }

  transaction(name, opts, fn) {
    if (typeof opts === "function") {
      fn = opts;
      opts = {};
    }
    let tx = null;
    try {
      const traceId =
        parseTraceparent((opts || {}).traceparent) || crypto.randomBytes(16).toString("hex");
      tx = new Transaction(this, name, (opts || {}).type || "request", traceId);
    } catch (err) {
      log(`failed to start transaction: ${err.message}`);
    }
    if (!tx) return fn(null); // instrumentation broke; the work still runs
    const fail = (err) => {
      // an escaping exception marks the transaction failed and is captured
      tx.failed = true;
      this._captureError(err, tx.name);
      tx.end();
    };
    return activeTransaction.run(tx, () => {
      let result;
      try {
        result = fn(tx);
      } catch (err) {
        fail(err);
        throw err; // re-thrown unchanged
      }
      if (result && typeof result.then === "function") {
        return result.then(
          (value) => {
            tx.end();
            return value;
          },
          (err) => {
            fail(err);
            throw err;
          }
        );
      }
      tx.end();
      return result;
    });
  }

  _recordTransaction(tx, durationMs, outcome) {
    // Guarded end to end: instrumentation must never throw into the app.
    try {
      // Trace-sample competition first: the slowest transactions win a slot
      // even when their group is dropped at the cap below.
      const samples = this._traceSamples;
      if (
        samples.length < MAX_TRACE_SAMPLES ||
        durationMs > Math.min(...samples.map((s) => s.duration_ms))
      ) {
        if (samples.length >= MAX_TRACE_SAMPLES) {
          samples.sort((a, b) => a.duration_ms - b.duration_ms);
          samples.shift();
        }
        const sample = {
          trace_id: tx.traceId,
          transaction_name: tx.name,
          transaction_type: tx.type,
          duration_ms: durationMs,
          started_at: new Date(tx.startedAt).toISOString(),
          outcome,
          spans_dropped: tx.spansDropped,
          spans: tx.spans.slice(),
        };
        if (tx.http && Object.keys(tx.http).length) sample.http = { ...tx.http };
        samples.push(sample);
      }
      const key = `${tx.name}\u0000${tx.type}`;
      let group = this._txBuffer.get(key);
      if (!group) {
        if (this._txBuffer.size >= MAX_TX_GROUPS) {
          this._warnThrottled(
            "tx-cap",
            `transaction buffer full at ${MAX_TX_GROUPS} groups; dropping new ones until next flush`
          );
          return;
        }
        group = {
          name: tx.name,
          type: tx.type,
          count: 0,
          sum: 0,
          min: durationMs,
          max: durationMs,
          success: 0,
          failed: 0,
          buckets: {},
          spans: new Map(),
        };
        this._txBuffer.set(key, group);
      }
      group.count += 1;
      group.sum = addFinite(group.sum, durationMs);
      group.min = Math.min(group.min, durationMs);
      group.max = Math.max(group.max, durationMs);
      group[outcome] += 1;
      addToBucket(group.buckets, durationMs);
      for (const [spanKey, row] of tx.breakdown) {
        let existing = group.spans.get(spanKey);
        if (!existing) {
          if (group.spans.size >= MAX_TX_BREAKDOWN_ROWS) {
            this._warnThrottled(
              `tx-breakdown:${tx.name}`,
              `transaction "${tx.name}" has more than ${MAX_TX_BREAKDOWN_ROWS} span breakdown rows; dropping the rest`
            );
            continue;
          }
          existing = { type: row.type, subtype: row.subtype, count: 0, sum: 0 };
          group.spans.set(spanKey, existing);
        }
        existing.count += row.count;
        existing.sum = addFinite(existing.sum, row.sum);
      }
    } catch (err) {
      log(`failed to record transaction: ${err.message}`);
    }
  }

  // -- errors ---------------------------------------------------------------

  captureException(err, opts = {}) {
    const handled = opts.handled !== false;
    const tx = currentTransaction();
    if (!handled && tx) tx.failed = true;
    this._captureError(err, tx ? tx.name : null);
  }

  _captureError(err, transactionName) {
    // Guarded end to end: error capture must never throw into the app.
    try {
      if (!(err instanceof Error)) {
        this._warnThrottled("capture-not-error", "captureException() got a non-Error value; ignoring");
        return;
      }
      const error = buildError(err);
      if (transactionName) error.transaction_name = transactionName;
      const existing = this._errorBuffer.get(error.fingerprint);
      if (existing) {
        existing.count += error.count;
      } else if (this._errorBuffer.size >= MAX_ERRORS) {
        this._warnThrottled(
          "error-cap",
          `error buffer full at ${MAX_ERRORS} distinct errors; dropping new ones until next flush`
        );
      } else {
        this._errorBuffer.set(error.fingerprint, error);
      }
    } catch (captureErr) {
      log(`failed to capture exception: ${captureErr.message}`);
    }
  }

  // -- structured logs ------------------------------------------------------

  log(level, message, attrs = null) {
    // Buffers one structured log entry for the next flush. Guarded end to
    // end: logging must never throw into the app.
    try {
      level = String(level).toLowerCase();
      if (!LOG_LEVELS.has(level)) {
        this._warnThrottled(`log-level:${level}`, `unknown log level "${level}"; recording as "info"`);
        level = "info";
      }
      let text = String(message === undefined || message === null ? "" : message);
      if (!text) {
        // the server rejects an empty message, and a rejected payload takes
        // the whole batch down with it
        this._warnThrottled("log-message-empty", "ignoring log entry with an empty message");
        return;
      }
      if (text.length > MAX_LOG_MESSAGE_LENGTH) {
        this._warnThrottled(
          "log-message-length",
          `log message longer than ${MAX_LOG_MESSAGE_LENGTH} chars; truncating`
        );
        text = text.slice(0, MAX_LOG_MESSAGE_LENGTH);
      }
      const entry = {
        service: this.service,
        level,
        message: text,
        timestamp: new Date().toISOString(),
      };
      const tx = currentTransaction();
      if (tx) entry.trace_id = tx.traceId;
      if (attrs && typeof attrs === "object" && Object.keys(attrs).length) entry.attrs = { ...attrs };
      if (this._logBuffer.length >= MAX_LOG_ENTRIES) {
        this._logBuffer.shift(); // drop-oldest: the freshest entries win
        this._warnThrottled(
          "log-cap",
          `log buffer full at ${MAX_LOG_ENTRIES} entries; dropping the oldest`
        );
      }
      this._logBuffer.push(entry);
    } catch (err) {
      log(`failed to record log entry: ${err.message}`);
    }
  }

  logger() {
    const bound = (level) => (message, attrs) => this.log(level, message, attrs);
    return { debug: bound("debug"), info: bound("info"), warn: bound("warn"), error: bound("error") };
  }

  // -- middleware -----------------------------------------------------------

  middleware() {
    return (req, res, next) => {
      let tx = null;
      const start = performance.now();
      try {
        const method = String(req.method || "GET").toUpperCase();
        const rawUrl = String(req.originalUrl || req.url || "/");
        const rawPath = rawUrl.split("?")[0];
        const name = `${method} ${normalizePath(rawPath)}`;
        const traceId =
          parseTraceparent(req.headers && req.headers.traceparent) ||
          crypto.randomBytes(16).toString("hex");
        tx = new Transaction(this, name, "request", traceId);
        const headers = req.headers || {};
        const remote = (req.socket && req.socket.remoteAddress) || null;
        // clientIp is the first X-Forwarded-For hop — the caller's claim
        // of the origin, spoofable by whoever sent the request. remoteIp
        // is always the socket peer, so the one address the kernel
        // vouches for survives whatever the header says.
        let forwarded = headers["x-forwarded-for"];
        if (Array.isArray(forwarded)) forwarded = forwarded[0];
        let clientIp = null;
        if (typeof forwarded === "string" && forwarded) {
          clientIp = forwarded.split(",")[0].trim() || null;
        }
        tx.setHttp({
          method,
          path: rawUrl,
          clientIp: clientIp || remote,
          remoteIp: remote,
          userAgent: headers["user-agent"] || null,
        });
        let finished = false;
        const finish = () => {
          try {
            if (finished) return;
            finished = true;
            const status = res.statusCode;
            const bucket =
              Number.isInteger(status) && status >= 100 && status <= 599
                ? `${Math.floor(status / 100)}xx`
                : "unknown";
            const tags = { method, status: bucket };
            this._record("http.request.duration", "timer", tags, "ms", performance.now() - start);
            this._record("http.requests", "counter", tags, null, 1);
            if (Number.isInteger(status)) tx.setHttp({ statusCode: status });
            if (bucket === "5xx") tx.failed = true;
            tx.end();
          } catch (err) {
            log(`failed to finish request transaction: ${err.message}`);
          }
        };
        res.on("finish", finish);
        res.on("close", finish);
      } catch (err) {
        log(`failed to start request transaction: ${err.message}`);
        tx = null;
      }
      if (tx) activeTransaction.run(tx, next);
      else next();
    };
  }

  // -- runtime metrics ------------------------------------------------------

  _snapshotRecord(snapshot, name, kind, unit, value) {
    // Direct write into the just-drained snapshot, bypassing the entry cap.
    const key = `${name}\u0000${tagsKey(this.tags)}`;
    const entry = { name, kind, unit, tags: { ...this.tags } };
    if (kind === "counter") {
      entry.count = 1;
      entry.sum = value;
      const old = snapshot.get(key);
      if (old && old.kind === "counter") {
        entry.count += old.count;
        entry.sum = addFinite(entry.sum, old.sum);
      }
    } else {
      entry.value = value;
    }
    snapshot.set(key, entry);
  }

  _recordRuntime(snapshot) {
    // Written straight into the drained snapshot: a full live buffer can
    // never starve these, and they don't count against the entry cap.
    try {
      this._snapshotRecord(snapshot, "process.memory.rss_bytes", "gauge", "bytes", process.memoryUsage().rss);
      const wall = performance.now();
      const usage = process.cpuUsage();
      const last = this._cpuSample;
      if (wall > last.wall) {
        const cpuMs = (usage.user - last.usage.user + usage.system - last.usage.system) / 1000;
        this._snapshotRecord(snapshot, "process.cpu.percent", "gauge", "%", (100 * cpuMs) / (wall - last.wall));
        this._cpuSample = { usage, wall };
      }
      this._snapshotRecord(snapshot, "process.uptime_seconds", "gauge", "s", (wall - this._started) / 1000);
      if (this._eventLoopDelay) {
        const meanMs = this._eventLoopDelay.mean / 1e6; // nanoseconds to ms
        if (Number.isFinite(meanMs)) {
          this._snapshotRecord(snapshot, "nodejs.eventloop.lag_ms", "gauge", "ms", meanMs);
        }
        this._eventLoopDelay.reset();
      }
      if (this._gcObserver) {
        this._snapshotRecord(snapshot, "nodejs.gc.collections", "counter", null, this._gcCollections);
        this._snapshotRecord(snapshot, "nodejs.gc.time_ms", "counter", "ms", this._gcTimeMs);
        this._gcCollections = 0;
        this._gcTimeMs = 0;
      }
      try {
        // _getActiveHandles is undocumented; tolerate its absence.
        const handles = process._getActiveHandles;
        if (typeof handles === "function") {
          this._snapshotRecord(snapshot, "nodejs.handles.active", "gauge", null, handles.call(process).length);
        }
      } catch (err) {
        log(`active-handle count unavailable: ${err.message}`);
      }
    } catch (err) {
      log(`runtime metrics collection failed: ${err.message}`);
    }
  }

  // -- flushing -------------------------------------------------------------

  flush() {
    // One flush at a time: concurrent flushes would race the cpu/gc baselines.
    this._flushChain = this._flushChain
      .then(() => this._doFlush())
      .catch((err) => log(`flush failed: ${err.message}`));
    return this._flushChain;
  }

  async _refreshProfileConfig() {
    // Ask the server whether to profile, and start or stop accordingly.
    //
    // FAILS CLOSED. If the config cannot be fetched -- network, auth, a
    // malformed response -- profiling does not start, and a running profiler
    // keeps the settings it already has rather than being torn down for a
    // transient blip. An SDK that defaults to *on* when the control plane is
    // unreachable is the wrong failure direction for code that runs inside
    // somebody else's process.
    const now = performance.now();
    if (now - this._profileConfigAt < PROFILE_CONFIG_INTERVAL_SECONDS * 1000) return;
    this._profileConfigAt = now;
    let fetched;
    try {
      fetched = await this._get(this.configUrl);
    } catch (err) {
      if (!this._profiler) {
        this._warnOnce(
          "profile_config",
          `profiling stays off: config could not be fetched from ${this.configUrl}: ${err.message}`
        );
      }
      return;
    }
    const config = clampProfileSettings(fetched);
    this._profileConfig = config;
    if (!config.profiling_enabled) {
      if (this._profiler) {
        log("profiling turned off from the RootTrace UI");
        this._profiler.stop();
        this._profiler = null;
      }
      return;
    }
    if (this._profiler) {
      const current = this._profiler._settings;
      const unchanged = Object.keys(config).every((k) => current[k] === config[k]);
      if (unchanged) return;
      // A rate change restarts the profiler: V8's sampling interval is fixed
      // when the session starts and cannot be retuned underneath it.
      log("profiling settings changed; restarting the profiler");
      this._profiler.stop();
      this._profiler = null;
    }
    try {
      const profiler = new CpuProfiler(config);
      profiler.start();
      this._profiler = profiler;
      // Set here, so the first upload covers a full configured window rather
      // than whatever fraction of one elapsed before the next metric flush.
      this._profileUploadAt = performance.now();
      log(`profiling on: V8 CPU at ${config.sample_rate_hz}Hz`);
    } catch (err) {
      // A Node built without the inspector, or a worker that cannot open a
      // session. Degrade to no profiling; everything else keeps working.
      this._warnOnce("profile_start", `profiling unavailable in this runtime: ${err.message}`);
      this._profiler = null;
    }
  }

  async _flushSecurityEvents() {
    if (!securityEvents.length) return;
    const events = securityEvents.splice(0, securityEvents.length);
    try {
      await this._post(this.securityUrl, {
        service: this.service,
        service_version: this.serviceVersion,
        deployment: this.deployment,
        events,
      });
    } catch (err) {
      this._warnOnce(
        "security_events",
        `dropping ${events.length} security events: upload to ${this.securityUrl} failed: ${err.message}`
      );
    }
  }

  async _flushProfile() {
    if (!this._profiler) return;
    // One upload per configured interval, not per metric flush: the metric
    // cadence defaults to 30s and can be set as low as 5s, which would cut
    // every profile into slivers and ignore upload_interval_seconds entirely
    // -- a setting the RootTrace UI offers and the server clamps. Monotonic,
    // for the same reason the config poll is.
    const interval = (this._profileConfig?.upload_interval_seconds ?? 60) * 1000;
    const now = performance.now();
    if (now - this._profileUploadAt < interval) return;
    this._profileUploadAt = now;
    let profile;
    try {
      profile = await this._profiler.drain();
    } catch (err) {
      log(`draining the CPU profile failed: ${err.message}`);
      return;
    }
    if (!profile) return;
    const payload = {
      service: this.service,
      service_version: this.serviceVersion,
      deployment: this.deployment,
      ...profile,
    };
    try {
      await this._send(payload, this.profilesUrl);
    } catch (err) {
      // Profiles are dropped rather than retried. They are large, they are
      // statistical, and a lost window leaves a slightly thinner flamegraph --
      // a far better outcome than a retry queue growing inside the customer's
      // process.
      this._warnOnce(
        "profile_upload",
        `dropping a profile: upload to ${this.profilesUrl} failed: ${err.message}`
      );
    }
  }

  _warnOnce(key, message) {
    // At most one warning per key per flush interval; _doFlush clears the set.
    if (this._warned.has(key)) return;
    this._warned.add(key);
    log(message);
  }

  _get(targetUrl) {
    return new Promise((resolve, reject) => {
      const url = new URL(targetUrl);
      const lib = url.protocol === "https:" ? https : http;
      const req = lib.request(
        {
          method: "GET",
          hostname: url.hostname,
          port: url.port || undefined,
          path: url.pathname + url.search,
          headers: {
            Authorization: `Collector ${this.token}`,
            Accept: "application/json",
            "User-Agent": `roottrace-apm-node/${VERSION}`,
            Connection: "close",
          },
          timeout: 10000,
          [kSelfRequest]: true, // never instrument our own control traffic
        },
        (res) => {
          const chunks = [];
          let size = 0;
          res.on("data", (chunk) => {
            // Bounded: this is parsed into a config that controls a sampling
            // loop, and an unbounded read from the network is not something to
            // do on the strength of the URL being ours.
            size += chunk.length;
            if (size > 256 * 1024) {
              req.destroy(new Error("config response too large"));
              return;
            }
            chunks.push(chunk);
          });
          res.on("end", () => {
            const body = Buffer.concat(chunks).toString("utf8");
            if (res.statusCode < 200 || res.statusCode >= 300) {
              reject(new HttpStatusError(res.statusCode, body, res.headers["retry-after"]));
              return;
            }
            try {
              resolve(JSON.parse(body));
            } catch (err) {
              reject(new Error(`config response was not JSON: ${err.message}`));
            }
          });
          res.on("error", reject);
        }
      );
      req.on("timeout", () => req.destroy(new Error("request timed out after 10s")));
      req.on("error", reject);
      req.end();
    });
  }

  async _doFlush() {
    if (Date.now() < this._retryAt) return;
    const snapshot = this._buffer;
    this._buffer = new Map();
    const txSnapshot = this._txBuffer;
    this._txBuffer = new Map();
    const errSnapshot = this._errorBuffer;
    this._errorBuffer = new Map();
    const traceSnapshot = this._traceSamples;
    this._traceSamples = [];
    const logSnapshot = this._logBuffer;
    this._logBuffer = [];
    this._warned.clear();
    if (this.runtimeMetrics) this._recordRuntime(snapshot);
    if (snapshot.size || txSnapshot.size || errSnapshot.size || traceSnapshot.length) {
      const payload = this._buildPayload(snapshot, txSnapshot, errSnapshot, traceSnapshot);
      try {
        await this._send(payload, this.ingestUrl);
      } catch (err) {
        if (err instanceof UnserializableError) {
          log(`dropping ${payload.metrics.length} unserializable metric entries: ${err.message}`);
        } else if (err instanceof HttpStatusError && err.code === 429) {
          this._pauseForRetryAfter(err);
          this._mergeBack(snapshot, txSnapshot, errSnapshot, traceSnapshot);
        } else if (err instanceof HttpStatusError && err.code >= 400 && err.code < 500) {
          // the API rejected the payload; resending it would fail forever
          log(`dropping ${payload.metrics.length} metric entries rejected by the API: ${err.message}`);
        } else {
          log(`flush of ${payload.metrics.length} metric entries to ${this.ingestUrl} failed: ${err.message}`);
          this._mergeBack(snapshot, txSnapshot, errSnapshot, traceSnapshot);
        }
      }
    }
    if (!logSnapshot.length) {
      await this._flushProfile();
      await this._flushSecurityEvents();
      return;
    }
    if (Date.now() < this._retryAt) {
      // the metric send above was just rate limited; hold the logs with it
      this._mergeBackLogs(logSnapshot);
      await this._flushProfile();
      await this._flushSecurityEvents();
      return;
    }
    try {
      await this._send({ logs: logSnapshot }, this.logsUrl);
    } catch (err) {
      if (err instanceof UnserializableError) {
        log(`dropping ${logSnapshot.length} unserializable log entries: ${err.message}`);
      } else if (err instanceof HttpStatusError && err.code === 429) {
        this._pauseForRetryAfter(err);
        this._mergeBackLogs(logSnapshot);
      } else if (err instanceof HttpStatusError && err.code >= 400 && err.code < 500) {
        log(`dropping ${logSnapshot.length} log entries rejected by the API: ${err.message}`);
      } else {
        log(`flush of ${logSnapshot.length} log entries to ${this.logsUrl} failed: ${err.message}`);
        this._mergeBackLogs(logSnapshot);
      }
    }
    await this._flushProfile();
  }

  _pauseForRetryAfter(err) {
    let delay = this.intervalSeconds;
    if (err.retryAfter !== undefined && err.retryAfter !== null) {
      const parsed = parseInt(err.retryAfter, 10);
      if (Number.isFinite(parsed)) delay = Math.max(parsed, 1);
      else log(`unparseable Retry-After "${err.retryAfter}"; retrying in ${delay}s`);
    }
    this._retryAt = Date.now() + delay * 1000;
    log(`rate limited (HTTP 429); pausing flushes for ${delay}s`);
  }

  _buildPayload(snapshot, txSnapshot, errSnapshot, traceSnapshot) {
    const metrics = [];
    for (const entry of snapshot.values()) {
      const metric = { name: entry.name, kind: entry.kind };
      if (entry.unit) metric.unit = entry.unit;
      if (entry.tags && Object.keys(entry.tags).length) metric.tags = entry.tags;
      for (const field of ["count", "sum", "min", "max", "value"]) {
        if (field in entry) metric[field] = entry[field];
      }
      if (entry.buckets) metric.buckets = { ...entry.buckets };
      metrics.push(metric);
    }
    const payload = {
      service: this.service,
      language: "nodejs",
      hostname: this.hostname,
      runtime: {
        language_version: process.versions.node,
        pid: process.pid,
        wrapper_version: VERSION,
      },
      interval_seconds: this.intervalSeconds,
      metrics,
    };
    if (this.serviceVersion) payload.service_version = this.serviceVersion;
    if (this._kubernetes) payload.kubernetes = { ...this._kubernetes };
    if (txSnapshot.size) {
      payload.transactions = [...txSnapshot.values()].map((group) => {
        const entry = {
          name: group.name,
          type: group.type,
          count: group.count,
          sum: group.sum,
          min: group.min,
          max: group.max,
          success: group.success,
          failed: group.failed,
          buckets: { ...group.buckets },
        };
        if (group.spans.size) {
          entry.spans = [...group.spans.values()].map((row) => {
            const spanRow = { type: row.type };
            if (row.subtype) spanRow.subtype = row.subtype;
            spanRow.count = row.count;
            spanRow.sum = row.sum;
            return spanRow;
          });
        }
        return entry;
      });
    }
    if (errSnapshot.size) payload.errors = [...errSnapshot.values()];
    if (traceSnapshot.length) {
      payload.trace_samples = [...traceSnapshot].sort((a, b) => b.duration_ms - a.duration_ms);
    }
    return payload;
  }

  _mergeBack(snapshot, txSnapshot, errSnapshot, traceSnapshot) {
    // Unsent aggregates fold into whatever accumulated meanwhile; the live
    // buffer is newer, so gauges keep the live value and the snapshot loses
    // ties for space at the caps. Guarded: flush's failure path must not throw.
    let dropped = 0;
    try {
      for (const [key, old] of snapshot) {
        const entry = this._buffer.get(key);
        if (!entry) {
          if (this._buffer.size >= MAX_USER_ENTRIES) {
            dropped += 1;
            continue;
          }
          this._buffer.set(key, old);
        } else if (entry.kind !== old.kind) {
          this._warnThrottled(
            `merge-kind:${key}`,
            `metric "${old.name}" changed kind from ${old.kind} to ${entry.kind} mid-flush; dropping unsent ${old.kind} data`
          );
        } else if (old.kind === "counter" || old.kind === "timer") {
          entry.count += old.count;
          entry.sum = addFinite(entry.sum, old.sum);
          if (old.kind === "timer") {
            entry.min = Math.min(entry.min, old.min);
            entry.max = Math.max(entry.max, old.max);
            mergeBuckets(entry.buckets, old.buckets);
          }
        }
      }
      for (const [key, old] of txSnapshot) {
        const group = this._txBuffer.get(key);
        if (!group) {
          if (this._txBuffer.size >= MAX_TX_GROUPS) {
            dropped += 1;
            continue;
          }
          this._txBuffer.set(key, old);
          continue;
        }
        group.count += old.count;
        group.sum = addFinite(group.sum, old.sum);
        group.min = Math.min(group.min, old.min);
        group.max = Math.max(group.max, old.max);
        group.success += old.success;
        group.failed += old.failed;
        mergeBuckets(group.buckets, old.buckets);
        for (const [spanKey, row] of old.spans) {
          const existing = group.spans.get(spanKey);
          if (!existing) {
            if (group.spans.size < MAX_TX_BREAKDOWN_ROWS) group.spans.set(spanKey, row);
          } else {
            existing.count += row.count;
            existing.sum = addFinite(existing.sum, row.sum);
          }
        }
      }
      for (const [fingerprint, old] of errSnapshot) {
        const entry = this._errorBuffer.get(fingerprint);
        if (!entry) {
          if (this._errorBuffer.size >= MAX_ERRORS) {
            dropped += 1;
            continue;
          }
          this._errorBuffer.set(fingerprint, old);
        } else {
          // the live entry is newer; keep its message and stack
          entry.count += old.count;
        }
      }
      if (traceSnapshot.length) {
        const combined = this._traceSamples.concat(traceSnapshot);
        combined.sort((a, b) => b.duration_ms - a.duration_ms);
        this._traceSamples = combined.slice(0, MAX_TRACE_SAMPLES);
      }
    } catch (err) {
      log(`merge-back of unsent entries failed; data lost: ${err.message}`);
    }
    if (dropped) log(`dropped ${dropped} unsent entries: buffers at their caps`);
  }

  _mergeBackLogs(logSnapshot) {
    // Unsent entries go back in front of whatever accumulated meanwhile;
    // at the cap the oldest are dropped. Guarded: flush's failure path
    // must not throw.
    try {
      const combined = logSnapshot.concat(this._logBuffer);
      const excess = combined.length - MAX_LOG_ENTRIES;
      this._logBuffer = excess > 0 ? combined.slice(excess) : combined;
      if (excess > 0) log(`dropped ${excess} unsent log entries: buffer at its cap`);
    } catch (err) {
      log(`merge-back of unsent log entries failed; data lost: ${err.message}`);
    }
  }

  _send(payload, targetUrl = this.ingestUrl) {
    let body;
    try {
      body = JSON.stringify(payload);
    } catch (err) {
      return Promise.reject(new UnserializableError(err.message));
    }
    return new Promise((resolve, reject) => {
      const url = new URL(targetUrl);
      const lib = url.protocol === "https:" ? https : http;
      const options = {
        method: "POST",
        hostname: url.hostname,
        port: url.port || undefined,
        path: url.pathname + url.search,
        headers: {
          Authorization: `Collector ${this.token}`,
          "Content-Type": "application/json",
          Accept: "application/json",
          "User-Agent": `roottrace-apm-node/${VERSION}`,
          "Content-Length": Buffer.byteLength(body),
          Connection: "close",
        },
        timeout: 10000,
        [kSelfRequest]: true, // never instrument our own flush traffic
      };
      const req = lib.request(options, (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve();
          } else {
            reject(
              new HttpStatusError(
                res.statusCode,
                Buffer.concat(chunks).toString("utf8"),
                res.headers["retry-after"]
              )
            );
          }
        });
        res.on("error", reject);
      });
      req.on("timeout", () => req.destroy(new Error("request timed out after 10s")));
      req.on("error", reject);
      req.end(body);
    });
  }

  shutdown() {
    // Clears the module singleton when this is the live instance.
    return instance === this ? shutdown() : this._shutdown();
  }

  async _shutdown() {
    if (this._profiler) {
      this._profiler.stop();
      this._profiler = null;
    }
    if (this._interval) {
      clearInterval(this._interval);
      this._interval = null;
    }
    await this.flush();
    if (Date.now() < this._retryAt) {
      // the final flush was a no-op behind the 429 deadline
      const abandoned = this._buffer.size;
      if (abandoned) {
        log(`shutting down while rate limited; abandoning ${abandoned} unsent metric entries`);
      }
      if (this._logBuffer.length) {
        log(`shutting down while rate limited; abandoning ${this._logBuffer.length} unsent log entries`);
      }
    }
    if (this._eventLoopDelay) this._eventLoopDelay.disable();
    if (this._gcObserver) this._gcObserver.disconnect();
  }
}

// ---------------------------------------------------------------------------
// Outbound HTTP instrumentation

let httpPatched = false;

function requestInfo(args, defaultProtocol) {
  // Extract url/options/callback from the request()/get() overloads.
  let url = null;
  let options = null;
  let cb;
  if (typeof args[0] === "string" || args[0] instanceof URL) {
    url = typeof args[0] === "string" ? new URL(args[0]) : args[0];
    if (typeof args[1] === "function") cb = args[1];
    else {
      options = args[1] || null;
      cb = args[2];
    }
  } else {
    options = args[0] || {};
    cb = args[1];
  }
  const protocol = (options && options.protocol) || (url && url.protocol) || defaultProtocol;
  let host = (options && (options.hostname || options.host)) || (url && url.hostname) || "localhost";
  host = String(host).replace(/:\d+$/, "");
  const port =
    (options && options.port) || (url && url.port) || (protocol === "https:" ? 443 : 80);
  const method = String((options && options.method) || "GET").toUpperCase();
  return { url, options, cb, destination: `${host}:${port}`, method };
}

function hasTraceparent(headers) {
  if (!headers) return false;
  return Object.keys(headers).some((k) => k.toLowerCase() === "traceparent");
}

function attachInstrumentation(req, info, tx, start, suppressed) {
  let done = false;
  const finish = (status) => {
    if (done) return;
    done = true;
    try {
      const apm = instance;
      if (!apm) return;
      const duration = performance.now() - start;
      const tags = { destination: info.destination, status };
      apm._record("http.client.duration", "timer", tags, "ms", duration);
      apm._record("http.client.requests", "counter", tags, null, 1);
      // suppressed: a db client (Elasticsearch) is timing this same call
      // as a db span; metrics record, the duplicate span does not.
      if (tx && !tx.closed && !suppressed) {
        tx._addSpan(`${info.method} ${info.destination}`, "http", info.destination, start - tx._start, duration);
      }
    } catch (err) {
      log(`outbound HTTP instrumentation failed: ${err.message}`);
    }
  };
  req.on("response", (res) => {
    const status = res.statusCode;
    const bucket =
      Number.isInteger(status) && status >= 100 && status <= 599
        ? `${Math.floor(status / 100)}xx`
        : "unknown";
    res.on("end", () => finish(bucket));
    res.on("close", () => finish(bucket));
    res.on("error", () => finish("error"));
  });
  req.on("error", () => finish("error"));
}

function wrapRequestFn(original, defaultProtocol) {
  return function (...args) {
    let info = null;
    let tx = null;
    try {
      const selfCall = args[0] && typeof args[0] === "object" && args[0][kSelfRequest];
      if (instance && !selfCall) {
        info = requestInfo(args, defaultProtocol);
        tx = currentTransaction();
        if (tx && !hasTraceparent(info.options && info.options.headers)) {
          const traceparent = `00-${tx.traceId}-${crypto.randomBytes(8).toString("hex")}-01`;
          const options = {
            ...(info.options || {}),
            headers: { ...((info.options && info.options.headers) || {}), traceparent },
          };
          // Rebuild the argument list around the cloned options object.
          args = info.url ? [info.url, options] : [options];
          if (info.cb) args.push(info.cb);
        }
      }
    } catch (err) {
      log(`outbound HTTP instrumentation failed: ${err.message}; sending the request uninstrumented`);
      info = null;
    }
    const req = original.apply(this, args); // the original runs exactly once
    try {
      if (info) attachInstrumentation(req, info, tx, performance.now(), spansSuppressed());
    } catch (err) {
      log(`outbound HTTP instrumentation failed: ${err.message}`);
    }
    return req;
  };
}

function instrumentHttp() {
  if (httpPatched) return; // idempotent
  const wrappedHttpRequest = wrapRequestFn(http.request, "http:");
  const wrappedHttpsRequest = wrapRequestFn(https.request, "https:");
  const wrappedHttpGet = wrapRequestFn(http.get, "http:");
  const wrappedHttpsGet = wrapRequestFn(https.get, "https:");
  http.request = wrappedHttpRequest;
  http.get = wrappedHttpGet;
  https.request = wrappedHttpsRequest;
  https.get = wrappedHttpsGet;
  httpPatched = true;
}

// ---------------------------------------------------------------------------
// fetch + database instrumentation
//
// Same contract as the HTTP hooks: patched at init(), missing libraries are
// silent no-ops, and instrumentation never throws into the application.

// True inside a db client's own instrumented call (Elasticsearch): the HTTP
// hooks then skip their span so one query is one waterfall row.
const suppressedSpans = new AsyncLocalStorage();

function spansSuppressed() {
  return suppressedSpans.getStore() === true;
}

function tryRequire(name) {
  // Resolves from the app's dependency tree (the agent lives in its
  // node_modules); an absent or unresolvable driver is simply not patched.
  try {
    return require(name);
  } catch (err) {
    void err;
    return null;
  }
}

function addDbSpan(name, subtype, start, tx) {
  try {
    if (!tx || tx.closed) return;
    tx._addSpan(name, "db", subtype, start - tx._start, performance.now() - start);
  } catch (err) {
    log(`db span recording failed: ${err.message}`);
  }
}

// Records around a promise without changing what the caller receives; the
// side listener marks rejections handled on its own branch only.
function spanOnSettle(result, name, subtype, start, tx) {
  if (result && typeof result.then === "function") {
    result.then(
      () => addDbSpan(name, subtype, start, tx),
      () => addDbSpan(name, subtype, start, tx)
    );
  }
  return result;
}

const SQL_TABLE_RE = /\b(?:from|into|update|join)\s+([A-Za-z0-9_."`]+)/i;

function sqlSpanName(statement) {
  // "SELECT users" / "INSERT orders": the operation plus a best-effort
  // table name, never the statement itself (parameters may be inlined).
  const text = String(statement == null ? "" : statement).trim();
  if (!text) return "SQL";
  const op = text.split(/\s+/, 1)[0].toUpperCase().slice(0, 20);
  const match = SQL_TABLE_RE.exec(text);
  return match ? `${op} ${match[1]}` : op;
}

let fetchPatched = false;

function instrumentFetch() {
  // Global fetch rides undici, not http.request, so it needs its own hook.
  if (fetchPatched || typeof globalThis.fetch !== "function") return;
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async function fetch(input, init) {
    let tx = null;
    let destination = null;
    let method = "GET";
    let start = null;
    let suppressed = false;
    try {
      if (instance) {
        tx = currentTransaction();
        suppressed = spansSuppressed();
        const raw =
          typeof input === "string" || input instanceof URL
            ? input
            : input && input.url;
        const url = new URL(String(raw));
        const port = url.port || (url.protocol === "https:" ? 443 : 80);
        destination = `${url.hostname}:${port}`;
        method = String(
          (init && init.method) ||
            (input && typeof input === "object" && input.method) ||
            "GET"
        ).toUpperCase();
        // Inject traceparent only for string/URL inputs: replacing the
        // headers of a Request object would drop its other headers.
        if (tx && (typeof input === "string" || input instanceof URL)) {
          const headers = new Headers((init && init.headers) || undefined);
          if (!headers.has("traceparent")) {
            headers.set(
              "traceparent",
              `00-${tx.traceId}-${crypto.randomBytes(8).toString("hex")}-01`
            );
            init = { ...(init || {}), headers };
          }
        }
        start = performance.now();
      }
    } catch (err) {
      log(`fetch instrumentation failed: ${err.message}; sending the request uninstrumented`);
      start = null;
    }

    const finish = (status) => {
      try {
        const apm = instance;
        if (start === null || !apm || !destination) return;
        const duration = performance.now() - start;
        const tags = { destination, status };
        apm._record("http.client.duration", "timer", tags, "ms", duration);
        apm._record("http.client.requests", "counter", tags, null, 1);
        if (tx && !tx.closed && !suppressed) {
          tx._addSpan(`${method} ${destination}`, "http", destination, start - tx._start, duration);
        }
      } catch (err) {
        log(`fetch instrumentation failed: ${err.message}`);
      }
    };

    let response;
    try {
      response = await originalFetch.call(this, input, init);
    } catch (err) {
      finish("error");
      throw err;
    }
    const status = response.status;
    finish(
      Number.isInteger(status) && status >= 100 && status <= 599
        ? `${Math.floor(status / 100)}xx`
        : "unknown"
    );
    return response;
  };
  fetchPatched = true;
}

let databasesPatched = false;

// find()/aggregate() return cursors synchronously; the I/O happens when the
// cursor drains, so those two record at toArray()/forEach() instead.
const MONGO_COLLECTION_METHODS = [
  "insertOne", "insertMany", "bulkWrite", "updateOne", "updateMany",
  "replaceOne", "deleteOne", "deleteMany", "findOne", "countDocuments",
  "estimatedDocumentCount", "distinct", "findOneAndDelete",
  "findOneAndReplace", "findOneAndUpdate",
];

function instrumentMongodb() {
  const mongodb = tryRequire("mongodb");
  if (!mongodb) return;
  const collectionProto = mongodb.Collection && mongodb.Collection.prototype;
  if (collectionProto) {
    for (const methodName of MONGO_COLLECTION_METHODS) {
      const original = collectionProto[methodName];
      if (typeof original !== "function") continue;
      collectionProto[methodName] = function (...args) {
        const tx = instance ? currentTransaction() : null;
        if (!tx) return original.apply(this, args);
        const start = performance.now();
        const name = `${methodName} ${this.dbName}.${this.collectionName}`;
        let result;
        try {
          result = original.apply(this, args);
        } catch (err) {
          addDbSpan(name, "mongodb", start, tx);
          throw err;
        }
        return spanOnSettle(result, name, "mongodb", start, tx);
      };
    }
  }
  const cursorProto = mongodb.AbstractCursor && mongodb.AbstractCursor.prototype;
  if (cursorProto) {
    for (const methodName of ["toArray", "forEach"]) {
      const original = cursorProto[methodName];
      if (typeof original !== "function") continue;
      cursorProto[methodName] = function (...args) {
        const tx = instance ? currentTransaction() : null;
        if (!tx) return original.apply(this, args);
        const start = performance.now();
        // FindCursor -> "find", AggregationCursor -> "aggregate"
        const op = (this.constructor.name || "Cursor").replace(/Cursor$/, "").toLowerCase() || "cursor";
        const name = `${op} ${this.namespace || ""}`.trim();
        let result;
        try {
          result = original.apply(this, args);
        } catch (err) {
          addDbSpan(name, "mongodb", start, tx);
          throw err;
        }
        return spanOnSettle(result, name, "mongodb", start, tx);
      };
    }
  }
}

// Connection upkeep, not application work.
const REDIS_SKIP_COMMANDS = new Set([
  "auth", "hello", "select", "info", "ping", "subscribe", "unsubscribe",
  "psubscribe", "punsubscribe", "ssubscribe", "sunsubscribe",
]);

function instrumentIoredis() {
  const Redis = tryRequire("ioredis");
  const proto = Redis && Redis.prototype;
  if (!proto || typeof proto.sendCommand !== "function") return;
  const original = proto.sendCommand;
  proto.sendCommand = function (command, ...rest) {
    const tx = instance ? currentTransaction() : null;
    const commandName = command && command.name ? String(command.name) : null;
    if (!tx || !commandName || REDIS_SKIP_COMMANDS.has(commandName.toLowerCase())) {
      return original.call(this, command, ...rest);
    }
    const start = performance.now();
    return spanOnSettle(
      original.call(this, command, ...rest),
      commandName.toUpperCase(), "redis", start, tx
    );
  };
}

function instrumentNodeRedis() {
  // node-redis v4/v5: the client class lives in @redis/client.
  const redisClient = tryRequire("@redis/client");
  const clientClass =
    (redisClient && redisClient.RedisClient) ||
    (tryRequire("@redis/client/dist/lib/client") || {}).default;
  const proto = clientClass && clientClass.prototype;
  if (!proto || typeof proto.sendCommand !== "function") return;
  const original = proto.sendCommand;
  proto.sendCommand = function (args, ...rest) {
    const tx = instance ? currentTransaction() : null;
    const commandName = Array.isArray(args) && args.length ? String(args[0]) : null;
    if (!tx || !commandName || REDIS_SKIP_COMMANDS.has(commandName.toLowerCase())) {
      return original.call(this, args, ...rest);
    }
    const start = performance.now();
    return spanOnSettle(
      original.call(this, args, ...rest),
      commandName.toUpperCase(), "redis", start, tx
    );
  };
}

function instrumentPg() {
  const pg = tryRequire("pg");
  const proto = pg && pg.Client && pg.Client.prototype;
  if (!proto || typeof proto.query !== "function") return;
  const original = proto.query;
  proto.query = function (...args) {
    const tx = instance ? currentTransaction() : null;
    if (!tx) return original.apply(this, args);
    const start = performance.now();
    const config = args[0];
    const name = sqlSpanName(typeof config === "string" ? config : config && config.text);
    // Callback form returns undefined; wrap the callback. Promise form
    // records on settle. Query-object form (submittable) passes through.
    for (let i = args.length - 1; i >= 0; i--) {
      if (typeof args[i] === "function") {
        const cb = args[i];
        args[i] = function (...cbArgs) {
          addDbSpan(name, "postgresql", start, tx);
          return cb.apply(this, cbArgs);
        };
        return original.apply(this, args);
      }
    }
    return spanOnSettle(original.apply(this, args), name, "postgresql", start, tx);
  };
}

function instrumentMysql2() {
  // The Connection class is only reachable via its module file; the path
  // has been stable for years but stays guarded regardless.
  const connection = tryRequire("mysql2/lib/connection.js");
  const proto = connection && connection.prototype;
  if (!proto) return;
  for (const methodName of ["query", "execute"]) {
    const original = proto[methodName];
    if (typeof original !== "function") continue;
    proto[methodName] = function (...args) {
      const tx = instance ? currentTransaction() : null;
      if (!tx) return original.apply(this, args);
      const sql = typeof args[0] === "string" ? args[0] : args[0] && args[0].sql;
      const name = sqlSpanName(sql);
      const start = performance.now();
      // mysql2's promise API always passes a callback underneath, so
      // wrapping the callback covers both styles.
      for (let i = args.length - 1; i >= 0; i--) {
        if (typeof args[i] === "function") {
          const cb = args[i];
          args[i] = function (...cbArgs) {
            addDbSpan(name, "mysql", start, tx);
            return cb.apply(this, cbArgs);
          };
          break;
        }
      }
      return original.apply(this, args);
    };
  }
}

function instrumentElasticsearch() {
  const transport = tryRequire("@elastic/transport");
  const proto = transport && transport.Transport && transport.Transport.prototype;
  if (!proto || typeof proto.request !== "function") return;
  const original = proto.request;
  proto.request = function (params, ...rest) {
    const tx = instance ? currentTransaction() : null;
    if (!tx) return original.apply(this, arguments);
    const start = performance.now();
    const method = (params && params.method) || "REQUEST";
    const name = `${method} ${normalizePath(String((params && params.path) || "/"))}`;
    let result;
    try {
      // The transport's own HTTP call is folded into this db span.
      result = suppressedSpans.run(true, () => original.call(this, params, ...rest));
    } catch (err) {
      addDbSpan(name, "elasticsearch", start, tx);
      throw err;
    }
    return spanOnSettle(result, name, "elasticsearch", start, tx);
  };
}

function instrumentDatabases() {
  if (databasesPatched) return; // idempotent
  for (const hook of [instrumentMongodb, instrumentIoredis, instrumentNodeRedis,
                      instrumentPg, instrumentMysql2, instrumentElasticsearch]) {
    try {
      hook();
    } catch (err) {
      log(`${hook.name} failed: ${err.message}; that client reports no spans`);
    }
  }
  databasesPatched = true;
}

// ---------------------------------------------------------------------------
// Module-level singleton

let instance = null;
let beforeExitHandler = null;

function init(opts = {}) {
  if (instance) {
    log("init() called again; returning the existing instance");
    return instance;
  }
  let service = opts.service || env("ROOTTRACE_APM_SERVICE");
  const token = opts.token || env("ROOTTRACE_APM_TOKEN") || env("ROOTTRACE_COLLECTOR_TOKEN");
  const apiUrl = opts.apiUrl || env("ROOTTRACE_API_URL", DEFAULT_API_URL) || DEFAULT_API_URL;
  if (!service) {
    throw new Error(
      "RootTrace APM needs a service name: pass service or set ROOTTRACE_APM_SERVICE"
    );
  }
  if (!token) {
    throw new Error(
      "RootTrace APM needs a collector token: pass token or set ROOTTRACE_APM_TOKEN (or ROOTTRACE_COLLECTOR_TOKEN)"
    );
  }
  let scheme = "";
  try {
    scheme = new URL(apiUrl).protocol;
  } catch (err) {
    void err; // fall through to the fail-fast below
  }
  if (scheme !== "http:" && scheme !== "https:") {
    throw new Error(
      `RootTrace APM needs an http(s) apiUrl, got "${apiUrl}": pass apiUrl or set ROOTTRACE_API_URL`
    );
  }
  let intervalSeconds = opts.intervalSeconds;
  if (intervalSeconds === undefined || intervalSeconds === null) {
    const raw = env("ROOTTRACE_APM_INTERVAL_SECONDS") || "30";
    intervalSeconds = Math.trunc(Number(raw));
    if (!Number.isFinite(intervalSeconds)) {
      log(`invalid ROOTTRACE_APM_INTERVAL_SECONDS "${raw}"; using 30`);
      intervalSeconds = 30;
    }
  } else {
    intervalSeconds = Math.trunc(Number(intervalSeconds));
    if (!Number.isFinite(intervalSeconds)) {
      throw new Error(`invalid intervalSeconds ${JSON.stringify(opts.intervalSeconds)}`);
    }
  }
  const clamped = Math.min(Math.max(intervalSeconds, 5), 3600);
  if (clamped !== intervalSeconds) {
    log(`intervalSeconds ${intervalSeconds} outside the server's 5-3600 range; using ${clamped}`);
  }
  service = String(service);
  if (service.length > MAX_SERVICE_LENGTH) {
    log(`service longer than ${MAX_SERVICE_LENGTH} chars; truncating`);
    service = service.slice(0, MAX_SERVICE_LENGTH);
  }
  let serviceVersion = opts.serviceVersion;
  if (serviceVersion === undefined || serviceVersion === null) {
    // Deploy pipelines set this without touching app code; versions power
    // the dashboard's deploy markers and regression checks.
    serviceVersion = env("ROOTTRACE_APM_SERVICE_VERSION") || null;
  }
  if (serviceVersion !== undefined && serviceVersion !== null) {
    serviceVersion = String(serviceVersion);
    if (serviceVersion.length > MAX_SERVICE_VERSION_LENGTH) {
      log(`serviceVersion longer than ${MAX_SERVICE_VERSION_LENGTH} chars; truncating`);
      serviceVersion = serviceVersion.slice(0, MAX_SERVICE_VERSION_LENGTH);
    }
  }
  instance = new Apm({
    service,
    token,
    apiUrl,
    intervalSeconds: clamped,
    tags: opts.tags,
    runtimeMetrics: opts.runtimeMetrics !== false,
    serviceVersion,
    deployment: opts.deployment !== undefined && opts.deployment !== null
      ? opts.deployment
      : env("ROOTTRACE_APM_DEPLOYMENT") || null,
    namespace: opts.namespace !== undefined && opts.namespace !== null
      ? opts.namespace
      : env("ROOTTRACE_APM_NAMESPACE") || null,
  });
  if (opts.httpInstrumentation !== false) {
    instrumentHttp();
    instrumentFetch();
  }
  if (opts.dbInstrumentation !== false) instrumentDatabases();
  if (opts.securitySinks !== false) instrumentSecuritySinks();
  instance._start();
  beforeExitHandler = () => {
    shutdown().catch((err) => log(`shutdown failed: ${err.message}`));
  };
  process.once("beforeExit", beforeExitHandler);
  return instance;
}

function flush() {
  return instance ? instance.flush() : Promise.resolve();
}

async function shutdown() {
  const apm = instance;
  if (!apm) return;
  instance = null; // a later init() builds a fresh instance
  if (beforeExitHandler) {
    process.removeListener("beforeExit", beforeExitHandler);
    beforeExitHandler = null;
  }
  await apm._shutdown();
}

module.exports = {
  init,
  flush,
  shutdown,
  VERSION,
  _internals: {
    Apm,
    reportSink,
    instrumentSecuritySinks,
    securityEvents,
    HttpStatusError,
    UnserializableError,
    parseTraceparent,
    tagsKey,
    normalizePath,
    bucketIndex,
    buildError,
    instrumentHttp,
    instrumentFetch,
    instrumentDatabases,
    sqlSpanName,
    suppressedSpans,
    detectKubernetes,
    deploymentFromPod,
    sanitizeK8sName,
    MAX_K8S_NAME_LENGTH,
    MAX_ENTRIES,
    MAX_USER_ENTRIES,
    MAX_TAG_KEYS,
    MAX_TX_GROUPS,
    MAX_ERRORS,
    MAX_LOG_ENTRIES,
    MAX_LOG_MESSAGE_LENGTH,
    CpuProfiler,
    clampProfileSettings,
    profileFrameName,
    PROFILE_BOUNDS,
    PROFILE_DEFAULTS,
  },
};
