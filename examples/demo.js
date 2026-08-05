"use strict";

// Minimal demo. Point it at a RootTrace API (or a dead endpoint to watch
// failure handling):
//
//   ROOTTRACE_API_URL=http://127.0.0.1:9/api node examples/demo.js
//
// The process exits on its own: the flush timer is unref'd and the
// beforeExit hook does one best-effort final flush.

const roottrace = require("../index.js");

const apm = roottrace.init({
  service: process.env.ROOTTRACE_APM_SERVICE || "demo-service",
  token: process.env.ROOTTRACE_APM_TOKEN || "rtc_demo_token",
  intervalSeconds: 5,
});

console.log("flushing to", apm.ingestUrl, "and", apm.logsUrl);

apm.counter("demo.orders.processed").add(3);
apm.gauge("demo.queue.depth").set(12);
apm.timer("demo.job.duration").record(38.2);

const logger = apm.logger();
logger.info("demo starting", { orders: 3 });

apm
  .transaction("GET /demo/:id", async (tx) => {
    const span = tx.startSpan("SELECT demo", "db", "sqlite");
    await new Promise((resolve) => setTimeout(resolve, 25));
    span.end();
    // inside a transaction, logs carry its trace id
    logger.warn("demo slow query", { duration_ms: 25 });
  })
  .then(() => {
    try {
      throw new Error("demo handled error");
    } catch (err) {
      apm.captureException(err);
    }
    return apm.flush();
  })
  .then(() => console.log("demo done"));
