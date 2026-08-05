import { IncomingMessage, ServerResponse } from "node:http";

export declare const VERSION: string;

export interface InitOptions {
  /** Service name (1-160 chars). Falls back to ROOTTRACE_APM_SERVICE. */
  service?: string;
  /** Collector token. Falls back to ROOTTRACE_APM_TOKEN, then ROOTTRACE_COLLECTOR_TOKEN. */
  token?: string;
  /** API base URL. Falls back to ROOTTRACE_API_URL, default https://api.roottrace.io/api. */
  apiUrl?: string;
  /** Flush interval, clamped to 5-3600. Falls back to ROOTTRACE_APM_INTERVAL_SECONDS, default 30. */
  intervalSeconds?: number;
  /** Instance-level tags merged into every metric (at most 8 keys). */
  tags?: Record<string, string>;
  /** Report process/Node runtime metrics each flush. Default true. */
  runtimeMetrics?: boolean;
  /** Deployed version of the app (max 64 chars). */
  serviceVersion?: string;
  /** Patch http/https and global fetch for outbound metrics, spans, and traceparent. Default true. */
  httpInstrumentation?: boolean;
  /** Auto-instrument installed database clients (mongodb, ioredis, node-redis, pg, mysql2, Elasticsearch) with db spans. Default true. */
  dbInstrumentation?: boolean;
  /** Kubernetes Deployment name (max 253 chars). Falls back to ROOTTRACE_APM_DEPLOYMENT, then in-cluster detection. */
  deployment?: string;
  /** Kubernetes namespace (max 253 chars). Falls back to ROOTTRACE_APM_NAMESPACE, then in-cluster detection. */
  namespace?: string;
}

export interface Counter {
  add(amount?: number): void;
}

export interface Gauge {
  set(value: number): void;
}

export interface Timer {
  record(durationMs: number): void;
  /** Times fn; supports sync and async functions (timed across the await). */
  time<T>(fn: () => T): T;
}

export interface SpanHandle {
  end(): void;
}

export interface TransactionOptions {
  /** Transaction type, e.g. "request" or "task". Default "request". */
  type?: string;
  /** Incoming W3C traceparent header value to adopt the trace id from. */
  traceparent?: string;
}

export interface HttpContext {
  /** HTTP method, e.g. "GET" (max 40 chars). */
  method?: string;
  /** Real request path, query string included (max 1024 chars). */
  path?: string;
  /** Response status code. */
  statusCode?: number;
  /** Claimed origin: first X-Forwarded-For hop (client-controlled), else the socket peer (max 64 chars). */
  clientIp?: string;
  /** The direct socket peer — the address the transport vouches for (max 64 chars). */
  remoteIp?: string;
  /** User-Agent header (max 300 chars). */
  userAgent?: string;
}

export interface Transaction {
  readonly name: string;
  readonly type: string;
  readonly traceId: string;
  readonly closed: boolean;
  startSpan(name: string, type?: string, subtype?: string | null): SpanHandle;
  setOutcome(outcome: "success" | "failed"): void;
  /** Attach request details; they ride the trace sample when this transaction is sampled. */
  setHttp(fields: HttpContext): void;
  captureException(err: Error): void;
  end(): void;
}

export interface CaptureOptions {
  /** false marks the active transaction failed. Default true. */
  handled?: boolean;
}

export type LogLevel = "debug" | "info" | "warn" | "error";

/** Level-bound versions of Apm.log(). */
export interface Logger {
  debug(message: string, attrs?: Record<string, unknown> | null): void;
  info(message: string, attrs?: Record<string, unknown> | null): void;
  warn(message: string, attrs?: Record<string, unknown> | null): void;
  error(message: string, attrs?: Record<string, unknown> | null): void;
}

export interface Apm {
  /** The resolved RootTrace API base URL. Read-only. */
  readonly apiUrl: string;
  /** The full flush target, `<apiUrl>/apm/ingest`. Read-only. */
  readonly ingestUrl: string;
  /** The log flush target, `<apiUrl>/logs/ingest`. Read-only. */
  readonly logsUrl: string;
  /** The resolved Kubernetes deployment name, or null. Read-only. */
  readonly deployment: string | null;
  /** The resolved Kubernetes namespace, or null. Read-only. */
  readonly namespace: string | null;

  counter(name: string, tags?: Record<string, string> | null, unit?: string | null): Counter;
  gauge(name: string, tags?: Record<string, string> | null, unit?: string | null): Gauge;
  timer(name: string, tags?: Record<string, string> | null, unit?: string): Timer;

  /** Runs fn inside a transaction; an escaping error is captured, marks it failed, and re-throws. */
  transaction<T>(name: string, fn: (tx: Transaction | null) => T): T;
  transaction<T>(name: string, opts: TransactionOptions, fn: (tx: Transaction | null) => T): T;
  /** Starts a transaction you end() yourself; it becomes the active transaction. */
  startTransaction(name: string, opts?: TransactionOptions): Transaction | null;

  captureException(err: Error, opts?: CaptureOptions): void;

  /** Buffer one structured log entry (message truncated at 8KB, 500 entries held,
   * oldest dropped first); batches ship on the flush interval with the trace id
   * of the active transaction, if any. Never throws. */
  log(level: LogLevel, message: string, attrs?: Record<string, unknown> | null): void;
  /** Level-bound log functions: `{debug, info, warn, error}`. */
  logger(): Logger;

  /** Express-compatible middleware creating one transaction per request. */
  middleware(): (req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void) => void;

  /** True while the V8 CPU profiler is running. Read-only: profiling is turned
   * on per service in the RootTrace UI and this SDK polls the API for it. */
  readonly profiling: boolean;

  flush(): Promise<void>;
  shutdown(): Promise<void>;
}

/** Configure the singleton and start the background flush loop. Fails fast on misconfiguration. */
export declare function init(options?: InitOptions): Apm;
/** Flush the singleton now; resolves when the send settles. */
export declare function flush(): Promise<void>;
/** Stop the flush loop, final-flush, and clear the singleton so init() works again. */
export declare function shutdown(): Promise<void>;
